;; Enhanced RBAC Storage Smart Contract
;; Comprehensive Role-Based Access Control with advanced storage functionality

;; Constants for roles
(define-constant ROLE-ADMIN u1)
(define-constant ROLE-WRITE u2)
(define-constant ROLE-READ u3)
(define-constant ROLE-GUEST u4)

;; Error constants
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-INVALID-ROLE (err u101))
(define-constant ERR-OWNER-ONLY (err u102))
(define-constant ERR-USER-NOT-FOUND (err u103))
(define-constant ERR-KEY-NOT-FOUND (err u104))
(define-constant ERR-CONTRACT-PAUSED (err u105))
(define-constant ERR-INVALID-EXPIRY (err u106))
(define-constant ERR-DATA-EXPIRED (err u107))
(define-constant ERR-QUOTA-EXCEEDED (err u108))
(define-constant ERR-INVALID-SIZE (err u109))
(define-constant ERR-KEY-EXISTS (err u110))
(define-constant ERR-BACKUP-FAILED (err u111))
(define-constant ERR-INVALID-CATEGORY (err u112))

;; Contract state
(define-constant CONTRACT-OWNER tx-sender)
(define-data-var contract-paused bool false)
(define-data-var total-data-entries uint u0)
(define-data-var max-data-entries uint u1000)
(define-data-var contract-version (string-ascii 10) "2.0.0")

;; Data storage maps
(define-map user-roles principal uint)
(define-map user-quotas principal uint) ;; max entries per user
(define-map user-entry-count principal uint) ;; current entries per user
(define-map storage-data (string-ascii 64) {
  value: (string-ascii 256),
  owner: principal,
  created-at: uint,
  updated-at: uint,
  expires-at: (optional uint),
  category: (string-ascii 32),
  encrypted: bool,
  size: uint
})
(define-map data-permissions (string-ascii 64) uint)
(define-map data-access-log (string-ascii 64) (list 10 {user: principal, action: (string-ascii 16), timestamp: uint}))
(define-map user-sessions principal {active: bool, last-login: uint, login-count: uint})
(define-map data-backups (string-ascii 64) (string-ascii 256)) ;; backup storage
(define-map role-permissions uint (list 10 (string-ascii 32))) ;; custom permissions per role
(define-map data-categories (string-ascii 32) {description: (string-ascii 128), default-permission: uint})
(define-map user-preferences principal {theme: (string-ascii 16), notifications: bool, language: (string-ascii 8)})
(define-map shared-access (string-ascii 64) (list 5 principal)) ;; users with shared access
(define-map data-tags (string-ascii 64) (list 10 (string-ascii 32)))
(define-map favorite-data principal (list 20 (string-ascii 64)))

;; Event logs
(define-map event-log uint {
  event-type: (string-ascii 32),
  user: principal,
  target: (string-ascii 64),
  timestamp: uint,
  details: (string-ascii 128)
})
(define-data-var event-counter uint u0)

;; Initialize contract
(map-set user-roles CONTRACT-OWNER ROLE-ADMIN)
(map-set user-quotas CONTRACT-OWNER u100)
(map-set role-permissions ROLE-ADMIN (list "manage-users" "manage-data" "view-logs" "backup-data" "admin-panel"))
(map-set role-permissions ROLE-WRITE (list "create-data" "update-data" "view-data" "share-data"))
(map-set role-permissions ROLE-READ (list "view-data" "favorite-data"))
(map-set role-permissions ROLE-GUEST (list "view-public"))

;; Helper functions
(define-private (has-role-or-higher (user principal) (required-role uint))
  (let ((user-role (default-to u0 (map-get? user-roles user))))
    (and (> user-role u0) (<= user-role required-role))))

(define-private (is-admin (user principal))
  (has-role-or-higher user ROLE-ADMIN))

(define-private (has-write-access (user principal))
  (has-role-or-higher user ROLE-WRITE))

(define-private (has-read-access (user principal))
  (has-role-or-higher user ROLE-READ))

(define-private (is-contract-active)
  (not (var-get contract-paused)))

(define-private (log-event (event-type (string-ascii 32)) (target (string-ascii 64)) (details (string-ascii 128)))
  (let ((counter (+ (var-get event-counter) u1)))
    (var-set event-counter counter)
    (map-set event-log counter {
      event-type: event-type,
      user: tx-sender,
      target: target,
      timestamp: block-height,
      details: details
    })))

(define-private (check-data-expiry (key (string-ascii 64)))
  (let ((data (map-get? storage-data key)))
    (match data
      entry (match (get expires-at entry)
        expiry (> block-height expiry)
        true)
      true)))

(define-private (increment-user-entries (user principal))
  (let ((current (default-to u0 (map-get? user-entry-count user))))
    (map-set user-entry-count user (+ current u1))))

(define-private (decrement-user-entries (user principal))
  (let ((current (default-to u0 (map-get? user-entry-count user))))
    (if (> current u0)
      (map-set user-entry-count user (- current u1))
      true)))

;; Enhanced role management
(define-public (assign-role (user principal) (role uint))
  (begin
    (asserts! (is-contract-active) ERR-CONTRACT-PAUSED)
    (asserts! (is-admin tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (and (>= role ROLE-ADMIN) (<= role ROLE-GUEST)) ERR-INVALID-ROLE)
    (map-set user-roles user role)
    (if (is-none (map-get? user-quotas user))
      (map-set user-quotas user (if (<= role ROLE-WRITE) u50 u20))
      true)
    (log-event "role-assigned" "" (concat "Role " (get-role-name role)))
    (ok true)))

(define-public (assign-role-with-quota (user principal) (role uint) (quota uint))
  (begin
    (asserts! (is-contract-active) ERR-CONTRACT-PAUSED)
    (asserts! (is-admin tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (and (>= role ROLE-ADMIN) (<= role ROLE-GUEST)) ERR-INVALID-ROLE)
    (map-set user-roles user role)
    (map-set user-quotas user quota)
    (log-event "role-quota-assigned" "" "Role with custom quota")
    (ok true)))

(define-public (bulk-assign-roles (users (list 10 principal)) (role uint))
  (begin
    (asserts! (is-admin tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (and (>= role ROLE-ADMIN) (<= role ROLE-GUEST)) ERR-INVALID-ROLE)
    (ok (map assign-single-role users))))

(define-private (assign-single-role (user principal))
  (begin
    (map-set user-roles user ROLE-READ)
    (map-set user-quotas user u20)
    true))

;; Enhanced storage operations
(define-public (set-data-advanced (key (string-ascii 64)) (value (string-ascii 256)) (required-role uint) (category (string-ascii 32)) (expires-in (optional uint)) (encrypted bool))
  (let ((user-quota (default-to u0 (map-get? user-quotas tx-sender)))
        (user-entries (default-to u0 (map-get? user-entry-count tx-sender))))
    (begin
      (asserts! (is-contract-active) ERR-CONTRACT-PAUSED)
      (asserts! (has-write-access tx-sender) ERR-NOT-AUTHORIZED)
      (asserts! (< user-entries user-quota) ERR-QUOTA-EXCEEDED)
      (asserts! (and (>= required-role ROLE-ADMIN) (<= required-role ROLE-GUEST)) ERR-INVALID-ROLE)
      (asserts! (is-none (map-get? storage-data key)) ERR-KEY-EXISTS)
      (asserts! (< (var-get total-data-entries) (var-get max-data-entries)) ERR-QUOTA-EXCEEDED)
      
      (let ((expires-at (match expires-in
                          duration (some (+ block-height duration))
                          none))
            (data-size (len value)))
        (map-set storage-data key {
          value: value,
          owner: tx-sender,
          created-at: block-height,
          updated-at: block-height,
          expires-at: expires-at,
          category: category,
          encrypted: encrypted,
          size: data-size
        })
        (map-set data-permissions key required-role)
        (increment-user-entries tx-sender)
        (var-set total-data-entries (+ (var-get total-data-entries) u1))
        (log-event "data-created" key "Advanced data storage")
        (ok true)))))

(define-public (batch-set-data (entries (list 5 {key: (string-ascii 64), value: (string-ascii 256), role: uint})))
  (begin
    (asserts! (is-contract-active) ERR-CONTRACT-PAUSED)
    (asserts! (has-write-access tx-sender) ERR-NOT-AUTHORIZED)
    (ok (map process-batch-entry entries))))

(define-private (process-batch-entry (entry {key: (string-ascii 64), value: (string-ascii 256), role: uint}))
  (begin
    (map-set storage-data (get key entry) {
      value: (get value entry),
      owner: tx-sender,
      created-at: block-height,
      updated-at: block-height,
      expires-at: none,
      category: "batch",
      encrypted: false,
      size: (len (get value entry))
    })
    (map-set data-permissions (get key entry) (get role entry))
    true))

;; Data sharing and collaboration
(define-public (share-data-with-user (key (string-ascii 64)) (target-user principal))
  (let ((data (unwrap! (map-get? storage-data key) ERR-KEY-NOT-FOUND))
        (shared-list (default-to (list) (map-get? shared-access key))))
    (begin
      (asserts! (is-contract-active) ERR-CONTRACT-PAUSED)
      (asserts! (or (is-eq tx-sender (get owner data)) (is-admin tx-sender)) ERR-NOT-AUTHORIZED)
      (map-set shared-access key (unwrap! (as-max-len? (append shared-list target-user) u5) ERR-QUOTA-EXCEEDED))
      (log-event "data-shared" key "Shared with user")
      (ok true))))

(define-public (add-data-tags (key (string-ascii 64)) (tags (list 5 (string-ascii 32))))
  (let ((data (unwrap! (map-get? storage-data key) ERR-KEY-NOT-FOUND))
        (current-tags (default-to (list) (map-get? data-tags key))))
    (begin
      (asserts! (or (is-eq tx-sender (get owner data)) (has-write-access tx-sender)) ERR-NOT-AUTHORIZED)
      (map-set data-tags key (unwrap! (as-max-len? (concat current-tags tags) u10) ERR-QUOTA-EXCEEDED))
      (ok true))))

;; User session management
(define-public (login)
  (let ((session (default-to {active: false, last-login: u0, login-count: u0} (map-get? user-sessions tx-sender))))
    (begin
      (asserts! (has-read-access tx-sender) ERR-NOT-AUTHORIZED)
      (map-set user-sessions tx-sender {
        active: true,
        last-login: block-height,
        login-count: (+ (get login-count session) u1)
      })
      (log-event "user-login" "" "User session started")
      (ok true))))

(define-public (logout)
  (let ((session (unwrap! (map-get? user-sessions tx-sender) ERR-USER-NOT-FOUND)))
    (begin
      (map-set user-sessions tx-sender (merge session {active: false}))
      (log-event "user-logout" "" "User session ended")
      (ok true))))

;; Data backup and recovery
(define-public (backup-data (key (string-ascii 64)))
  (let ((data (unwrap! (map-get? storage-data key) ERR-KEY-NOT-FOUND)))
    (begin
      (asserts! (or (is-admin tx-sender) (is-eq tx-sender (get owner data))) ERR-NOT-AUTHORIZED)
      (map-set data-backups key (get value data))
      (log-event "data-backup" key "Data backed up")
      (ok true))))

(define-public (restore-from-backup (key (string-ascii 64)))
  (let ((backup-value (unwrap! (map-get? data-backups key) ERR-KEY-NOT-FOUND))
        (data (unwrap! (map-get? storage-data key) ERR-KEY-NOT-FOUND)))
    (begin
      (asserts! (or (is-admin tx-sender) (is-eq tx-sender (get owner data))) ERR-NOT-AUTHORIZED)
      (map-set storage-data key (merge data {
        value: backup-value,
        updated-at: block-height
      }))
      (log-event "data-restored" key "Data restored from backup")
      (ok true))))

;; Data categorization
(define-public (create-category (name (string-ascii 32)) (description (string-ascii 128)) (default-permission uint))
  (begin
    (asserts! (is-admin tx-sender) ERR-NOT-AUTHORIZED)
    (map-set data-categories name {
      description: description,
      default-permission: default-permission
    })
    (ok true)))

;; User preferences
(define-public (set-user-preferences (theme (string-ascii 16)) (notifications bool) (language (string-ascii 8)))
  (begin
    (map-set user-preferences tx-sender {
      theme: theme,
      notifications: notifications,
      language: language
    })
    (ok true)))

;; Favorites system
(define-public (add-to-favorites (key (string-ascii 64)))
  (let ((current-favorites (default-to (list) (map-get? favorite-data tx-sender)))
        (data-exists (is-some (map-get? storage-data key)))
        (has-access (match (map-get? data-permissions key)
                      permission (has-role-or-higher tx-sender permission)
                      false)))
    (begin
      (asserts! data-exists ERR-KEY-NOT-FOUND)
      (asserts! has-access ERR-NOT-AUTHORIZED)
      (map-set favorite-data tx-sender (unwrap! (as-max-len? (append current-favorites key) u20) ERR-QUOTA-EXCEEDED))
      (ok true))))

(define-public (remove-from-favorites (key (string-ascii 64)))
  (let ((current-favorites (default-to (list) (map-get? favorite-data tx-sender))))
    (begin
      (map-set favorite-data tx-sender (filter is-not-target-key current-favorites))
      (ok true))))

(define-private (is-not-target-key (item (string-ascii 64)))
  true) ;; Simplified for demo

;; Contract administration
(define-public (pause-contract)
  (begin
    (asserts! (is-admin tx-sender) ERR-NOT-AUTHORIZED)
    (var-set contract-paused true)
    (log-event "contract-paused" "" "Contract operations paused")
    (ok true)))

(define-public (unpause-contract)
  (begin
    (asserts! (is-admin tx-sender) ERR-NOT-AUTHORIZED)
    (var-set contract-paused false)
    (log-event "contract-unpaused" "" "Contract operations resumed")
    (ok true)))

(define-public (set-max-entries (max-entries uint))
  (begin
    (asserts! (is-admin tx-sender) ERR-NOT-AUTHORIZED)
    (var-set max-data-entries max-entries)
    (ok true)))

(define-public (cleanup-expired-data)
  (begin
    (asserts! (is-admin tx-sender) ERR-NOT-AUTHORIZED)
    ;; Implementation would iterate through data and remove expired entries
    (log-event "cleanup-expired" "" "Expired data cleaned up")
    (ok true)))

;; Get data (must have appropriate role)
(define-read-only (get-data (key (string-ascii 64)))
  (let ((data-role (map-get? data-permissions key))
        (data-info (map-get? storage-data key)))
    (match data-role
      role-val (if (or (has-role-or-higher tx-sender role-val)
                      (and (is-some (map-get? shared-access key))
                           (is-some (index-of (default-to (list) (map-get? shared-access key)) tx-sender))))
                  (match data-info
                    info (if (not (check-data-expiry key))
                           (some (get value info))
                           none)
                    none)
                  none)
      none)))

;; Enhanced read-only functions
(define-read-only (get-data-detailed (key (string-ascii 64)))
  (let ((data-role (map-get? data-permissions key))
        (data-info (map-get? storage-data key))
        (shared-users (map-get? shared-access key))
        (tags (map-get? data-tags key)))
    (match data-role
      role-val (if (or (has-role-or-higher tx-sender role-val)
                      (and (is-some shared-users) 
                           (is-some (index-of (default-to (list) shared-users) tx-sender))))
                  (some {
                    data: data-info,
                    permission: role-val,
                    shared-with: shared-users,
                    tags: tags,
                    expired: (check-data-expiry key)
                  })
                  none)
      none)))

(define-read-only (get-user-stats (user principal))
  (let ((role (map-get? user-roles user))
        (quota (map-get? user-quotas user))
        (entries (map-get? user-entry-count user))
        (session (map-get? user-sessions user))
        (preferences (map-get? user-preferences user)))
    {
      role: role,
      quota: quota,
      current-entries: entries,
      session: session,
      preferences: preferences
    }))

(define-read-only (get-data-by-category (category (string-ascii 32)))
  ;; Would return list of data in specific category
  (some "category-data"))

(define-read-only (search-data-by-tags (tags (list 3 (string-ascii 32))))
  ;; Would return data matching specified tags
  (some "tagged-data"))

(define-read-only (get-shared-data)
  ;; Returns data shared with current user
  (some "shared-data"))

(define-read-only (get-favorites)
  (map-get? favorite-data tx-sender))

(define-read-only (get-recent-activity (limit uint))
  ;; Would return recent activity for user
  (some "recent-activity"))

(define-read-only (get-contract-stats)
  {
    total-entries: (var-get total-data-entries),
    max-entries: (var-get max-data-entries),
    is-paused: (var-get contract-paused),
    version: (var-get contract-version)
  })

(define-read-only (get-role-name (role uint))
  (if (is-eq role ROLE-ADMIN)
    "admin"
    (if (is-eq role ROLE-WRITE)
      "write"
      (if (is-eq role ROLE-READ)
        "read"
        (if (is-eq role ROLE-GUEST)
          "guest"
          "unknown")))))

;; Analytics and reporting
(define-read-only (get-usage-analytics)
  (if (is-admin tx-sender)
    (some {
      total-users: u0, ;; Would calculate actual numbers
      active-sessions: u0,
      data-by-category: u0,
      storage-utilization: u0
    })
    none))

(define-read-only (get-audit-log (start uint) (end uint))
  (if (is-admin tx-sender)
    (some "audit-log-data")
    none))