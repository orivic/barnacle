;; FileBackup Smart Contract
;; Purpose: Create backup copies of files with separate backup nodes

;; Constants
(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_NOT_FOUND (err u101))
(define-constant ERR_ALREADY_EXISTS (err u102))
(define-constant ERR_INVALID_STATUS (err u103))
(define-constant ERR_INSUFFICIENT_BACKUP_NODES (err u104))
(define-constant ERR_BACKUP_FAILED (err u105))

;; Data Variables
(define-data-var next-backup-id uint u1)
(define-data-var min-backup-replicas uint u3)

;; Data Maps

;; Backup Nodes Registry
(define-map backup-nodes
    { node-id: principal }
    {
        reputation-score: uint,
        total-backups: uint,
        successful-backups: uint,
        failed-backups: uint,
        is-active: bool,
        storage-capacity: uint,
        used-capacity: uint,
        registration-block: uint
    }
)

;; Backup Requests
(define-map backup-requests
    { backup-id: uint }
    {
        file-hash: (string-ascii 64),
        file-size: uint,
        owner: principal,
        priority: uint, ;; 1=low, 2=medium, 3=high
        created-at: uint,
        status: (string-ascii 20), ;; "pending", "in-progress", "completed", "failed"
        required-replicas: uint,
        backup-reward: uint
    }
)

;; Backup Assignments (which nodes are backing up which files)
(define-map backup-assignments
    { backup-id: uint, node-id: principal }
    {
        assigned-at: uint,
        backup-status: (string-ascii 20), ;; "assigned", "backing-up", "completed", "failed"
        backup-hash: (optional (string-ascii 64)),
        completed-at: (optional uint)
    }
)

;; File Backup Locations (for restore process)
(define-map file-backup-locations
    { file-hash: (string-ascii 64), node-id: principal }
    {
        backup-id: uint,
        backup-hash: (string-ascii 64),
        created-at: uint,
        last-verified: uint,
        is-verified: bool
    }
)

;; Restore Requests
(define-map restore-requests
    { restore-id: uint }
    {
        file-hash: (string-ascii 64),
        requester: principal,
        selected-node: principal,
        created-at: uint,
        status: (string-ascii 20), ;; "pending", "in-progress", "completed", "failed"
        restore-reward: uint
    }
)

(define-data-var next-restore-id uint u1)

;; Read-only functions

;; Get backup node info
(define-read-only (get-backup-node (node-id principal))
    (map-get? backup-nodes { node-id: node-id })
)

;; Get backup request info
(define-read-only (get-backup-request (backup-id uint))
    (map-get? backup-requests { backup-id: backup-id })
)

;; Get backup assignment info
(define-read-only (get-backup-assignment (backup-id uint) (node-id principal))
    (map-get? backup-assignments { backup-id: backup-id, node-id: node-id })
)

;; Get file backup locations
(define-read-only (get-file-backup-locations (file-hash (string-ascii 64)) (node-id principal))
    (map-get? file-backup-locations { file-hash: file-hash, node-id: node-id })
)

;; Get restore request info
(define-read-only (get-restore-request (restore-id uint))
    (map-get? restore-requests { restore-id: restore-id })
)

;; Check if node is active backup node
(define-read-only (is-active-backup-node (node-id principal))
    (match (map-get? backup-nodes { node-id: node-id })
        node-info (get is-active node-info)
        false
    )
)

;; Get next backup ID
(define-read-only (get-next-backup-id)
    (var-get next-backup-id)
)

;; Public functions

;; Register as backup node
(define-public (register-backup-node (storage-capacity uint))
    (let ((node-id tx-sender))
        (asserts! (is-none (map-get? backup-nodes { node-id: node-id })) ERR_ALREADY_EXISTS)
        (ok (map-set backup-nodes
            { node-id: node-id }
            {
                reputation-score: u100,
                total-backups: u0,
                successful-backups: u0,
                failed-backups: u0,
                is-active: true,
                storage-capacity: storage-capacity,
                used-capacity: u0,
                registration-block: block-height
            }
        ))
    )
)

;; Update backup node status
(define-public (update-backup-node-status (is-active bool))
    (let ((node-id tx-sender))
        (match (map-get? backup-nodes { node-id: node-id })
            node-info
            (ok (map-set backup-nodes
                { node-id: node-id }
                (merge node-info { is-active: is-active })
            ))
            ERR_NOT_FOUND
        )
    )
)

;; Create backup request
(define-public (create-backup-request 
    (file-hash (string-ascii 64))
    (file-size uint)
    (priority uint)
    (required-replicas uint)
    (backup-reward uint))
    (let ((backup-id (var-get next-backup-id)))
        (asserts! (and (>= priority u1) (<= priority u3)) ERR_INVALID_STATUS)
        (asserts! (>= required-replicas u1) ERR_INVALID_STATUS)
        
        (map-set backup-requests
            { backup-id: backup-id }
            {
                file-hash: file-hash,
                file-size: file-size,
                owner: tx-sender,
                priority: priority,
                created-at: block-height,
                status: "pending",
                required-replicas: required-replicas,
                backup-reward: backup-reward
            }
        )
        
        (var-set next-backup-id (+ backup-id u1))
        (ok backup-id)
    )
)

;; Assign backup to node (called by contract or authorized party)
(define-public (assign-backup-to-node (backup-id uint) (node-id principal))
    (match (map-get? backup-requests { backup-id: backup-id })
        request-info
        (match (map-get? backup-nodes { node-id: node-id })
            node-info
            (begin
                (asserts! (get is-active node-info) ERR_UNAUTHORIZED)
                (asserts! (is-eq (get status request-info) "pending") ERR_INVALID_STATUS)
                
                ;; Check if node has sufficient capacity
                (asserts! (>= (- (get storage-capacity node-info) (get used-capacity node-info)) 
                             (get file-size request-info)) 
                         ERR_INSUFFICIENT_BACKUP_NODES)
                
                ;; Create assignment
                (map-set backup-assignments
                    { backup-id: backup-id, node-id: node-id }
                    {
                        assigned-at: block-height,
                        backup-status: "assigned",
                        backup-hash: none,
                        completed-at: none
                    }
                )
                
                ;; Update request status to in-progress
                (map-set backup-requests
                    { backup-id: backup-id }
                    (merge request-info { status: "in-progress" })
                )
                
                (ok true)
            )
            ERR_NOT_FOUND
        )
        ERR_NOT_FOUND
    )
)

;; Report backup completion (called by backup node)
(define-public (report-backup-completion 
    (backup-id uint) 
    (backup-hash (string-ascii 64)))
    (let ((node-id tx-sender))
        (match (map-get? backup-assignments { backup-id: backup-id, node-id: node-id })
            assignment-info
            (match (map-get? backup-requests { backup-id: backup-id })
                request-info
                (begin
                    (asserts! (is-eq (get backup-status assignment-info) "assigned") ERR_INVALID_STATUS)
                    
                    ;; Update assignment
                    (map-set backup-assignments
                        { backup-id: backup-id, node-id: node-id }
                        (merge assignment-info {
                            backup-status: "completed",
                            backup-hash: (some backup-hash),
                            completed-at: (some block-height)
                        })
                    )
                    
                    ;; Add to backup locations
                    (map-set file-backup-locations
                        { file-hash: (get file-hash request-info), node-id: node-id }
                        {
                            backup-id: backup-id,
                            backup-hash: backup-hash,
                            created-at: block-height,
                            last-verified: block-height,
                            is-verified: true
                        }
                    )
                    
                    ;; Update node stats
                    (match (map-get? backup-nodes { node-id: node-id })
                        node-info
                        (map-set backup-nodes
                            { node-id: node-id }
                            (merge node-info {
                                total-backups: (+ (get total-backups node-info) u1),
                                successful-backups: (+ (get successful-backups node-info) u1),
                                used-capacity: (+ (get used-capacity node-info) (get file-size request-info))
                            })
                        )
                        false
                    )
                    
                    (ok true)
                )
                ERR_NOT_FOUND
            )
            ERR_NOT_FOUND
        )
    )
)

;; Report backup failure (called by backup node)
(define-public (report-backup-failure (backup-id uint))
    (let ((node-id tx-sender))
        (match (map-get? backup-assignments { backup-id: backup-id, node-id: node-id })
            assignment-info
            (begin
                ;; Update assignment status
                (map-set backup-assignments
                    { backup-id: backup-id, node-id: node-id }
                    (merge assignment-info { backup-status: "failed" })
                )
                
                ;; Update node stats
                (match (map-get? backup-nodes { node-id: node-id })
                    node-info
                    (map-set backup-nodes
                        { node-id: node-id }
                        (merge node-info {
                            total-backups: (+ (get total-backups node-info) u1),
                            failed-backups: (+ (get failed-backups node-info) u1)
                        })
                    )
                    false
                )
                
                (ok true)
            )
            ERR_NOT_FOUND
        )
    )
)

;; Create restore request
(define-public (create-restore-request 
    (file-hash (string-ascii 64))
    (preferred-node (optional principal))
    (restore-reward uint))
    (let ((restore-id (var-get next-restore-id)))
        ;; TODO: Add logic to select best available node if preferred-node is none
        (let ((selected-node (default-to CONTRACT_OWNER preferred-node)))
            (map-set restore-requests
                { restore-id: restore-id }
                {
                    file-hash: file-hash,
                    requester: tx-sender,
                    selected-node: selected-node,
                    created-at: block-height,
                    status: "pending",
                    restore-reward: restore-reward
                }
            )
            
            (var-set next-restore-id (+ restore-id u1))
            (ok restore-id)
        )
    )
)

;; Complete restore process (called by backup node)
(define-public (complete-restore (restore-id uint))
    (match (map-get? restore-requests { restore-id: restore-id })
        restore-info
        (begin
            (asserts! (is-eq tx-sender (get selected-node restore-info)) ERR_UNAUTHORIZED)
            (asserts! (is-eq (get status restore-info) "pending") ERR_INVALID_STATUS)
            
            (map-set restore-requests
                { restore-id: restore-id }
                (merge restore-info { status: "completed" })
            )
            
            (ok true)
        )
        ERR_NOT_FOUND
    )
)

;; Verify backup integrity (called by backup node)
(define-public (verify-backup-integrity 
    (file-hash (string-ascii 64))
    (is-verified bool))
    (let ((node-id tx-sender))
        (match (map-get? file-backup-locations { file-hash: file-hash, node-id: node-id })
            location-info
            (begin
                (map-set file-backup-locations
                    { file-hash: file-hash, node-id: node-id }
                    (merge location-info {
                        last-verified: block-height,
                        is-verified: is-verified
                    })
                )
                (ok true)
            )
            ERR_NOT_FOUND
        )
    )
)

;; Admin function to update minimum backup replicas
(define-public (set-min-backup-replicas (new-min uint))
    (begin
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
        (var-set min-backup-replicas new-min)
        (ok true)
    )
)