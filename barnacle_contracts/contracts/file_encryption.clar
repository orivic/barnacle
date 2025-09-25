;; FileEncryption Smart Contract
;; Purpose: Store encryption metadata for files with access control and key rotation

;; Constants
(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_FILE_NOT_FOUND (err u101))
(define-constant ERR_INVALID_KEY (err u102))
(define-constant ERR_KEY_ALREADY_EXISTS (err u103))
(define-constant ERR_INVALID_ROTATION (err u104))
(define-constant ERR_INVALID_INPUT (err u105))
(define-constant ERR_INVALID_PRINCIPAL (err u106))
(define-constant ERR_BUFFER_TOO_LARGE (err u107))
(define-constant ERR_STRING_TOO_LONG (err u108))

;; Input validation constants
(define-constant MAX_REASON_LENGTH u100)
(define-constant REQUIRED_KEY_LENGTH u64)
(define-constant REQUIRED_HASH_LENGTH u32)
(define-constant MAX_FILES_PER_USER u1000)

;; Data Variables
(define-data-var next-file-id uint u1)

;; Track files per user to prevent spam
(define-map user-file-count
  principal
  uint
)

;; Data Maps

;; Store file encryption metadata
(define-map file-metadata
  uint ;; file-id
  {
    file-hash: (buff 32),
    owner: principal,
    public-key: (buff 64),
    created-at: uint,
    last-rotated: uint,
    rotation-count: uint,
    is-active: bool
  }
)

;; Store access permissions for files
(define-map file-access
  {file-id: uint, user: principal}
  {
    can-read: bool,
    can-write: bool,
    granted-at: uint,
    granted-by: principal
  }
)

;; Store key rotation history
(define-map key-rotation-history
  {file-id: uint, rotation-id: uint}
  {
    old-key: (buff 64),
    new-key: (buff 64),
    rotated-at: uint,
    rotated-by: principal,
    reason: (string-ascii 100)
  }
)

;; Store authorized key managers
(define-map key-managers
  principal
  bool
)

;; Input validation functions

;; Validate public key format and length
(define-private (validate-public-key (key (buff 64)))
  (and 
    (is-eq (len key) REQUIRED_KEY_LENGTH)
    (not (is-eq key 0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000))
  )
)

;; Validate file hash format and length  
(define-private (validate-file-hash (hash (buff 32)))
  (and
    (is-eq (len hash) REQUIRED_HASH_LENGTH)
    (not (is-eq hash 0x0000000000000000000000000000000000000000000000000000000000000000))
  )
)

;; Validate reason string length and content
(define-private (validate-reason (reason (string-ascii 100)))
  (and
    (<= (len reason) MAX_REASON_LENGTH)
    (> (len reason) u0)
  )
)

;; Validate principal is not null/invalid
(define-private (validate-principal (user principal))
  (not (is-eq user 'ST000000000000000000002AMW42H))
)

;; Check if user has reached file limit
(define-private (check-file-limit (user principal))
  (let (
    (current-count (default-to u0 (map-get? user-file-count user)))
  )
    (< current-count MAX_FILES_PER_USER)
  )
)

;; Sanitize and validate file ID
(define-private (validate-file-id (file-id uint))
  (and
    (> file-id u0)
    (< file-id (var-get next-file-id))
  )
)

;; Read-only Functions

;; Get file metadata by ID (with input validation)
(define-read-only (get-file-metadata (file-id uint))
  (if (validate-file-id file-id)
    (map-get? file-metadata file-id)
    none
  )
)

;; Get file access permissions (with validation)
(define-read-only (get-file-access (file-id uint) (user principal))
  (if (and (validate-file-id file-id) (validate-principal user))
    (map-get? file-access {file-id: file-id, user: user})
    none
  )
)

;; Get key rotation history
(define-read-only (get-rotation-history (file-id uint) (rotation-id uint))
  (map-get? key-rotation-history {file-id: file-id, rotation-id: rotation-id})
)

;; Check if user has read access to file
(define-read-only (has-read-access (file-id uint) (user principal))
  (let (
    (file-data (unwrap! (get-file-metadata file-id) false))
    (access-data (get-file-access file-id user))
  )
    (or 
      (is-eq (get owner file-data) user)
      (and 
        (is-some access-data)
        (get can-read (unwrap-panic access-data))
      )
    )
  )
)

;; Check if user has write access to file
(define-read-only (has-write-access (file-id uint) (user principal))
  (let (
    (file-data (unwrap! (get-file-metadata file-id) false))
    (access-data (get-file-access file-id user))
  )
    (or 
      (is-eq (get owner file-data) user)
      (and 
        (is-some access-data)
        (get can-write (unwrap-panic access-data))
      )
    )
  )
)

;; Check if user is authorized key manager
(define-read-only (is-key-manager (user principal))
  (default-to false (map-get? key-managers user))
)

;; Get current file ID counter
(define-read-only (get-next-file-id)
  (var-get next-file-id)
)

;; Public Functions

;; Register a new encrypted file (with comprehensive validation)
(define-public (register-file (file-hash (buff 32)) (public-key (buff 64)))
  (let (
    (file-id (var-get next-file-id))
    (current-user-files (default-to u0 (map-get? user-file-count tx-sender)))
  )
    ;; Validate all inputs
    (asserts! (validate-file-hash file-hash) ERR_INVALID_INPUT)
    (asserts! (validate-public-key public-key) ERR_INVALID_KEY)
    (asserts! (check-file-limit tx-sender) ERR_INVALID_INPUT)
    
    ;; Store file metadata
    (map-set file-metadata file-id {
      file-hash: file-hash,
      owner: tx-sender,
      public-key: public-key,
      created-at: block-height,
      last-rotated: block-height,
      rotation-count: u0,
      is-active: true
    })
    
    ;; Update user file count
    (map-set user-file-count tx-sender (+ current-user-files u1))
    
    ;; Increment file ID counter
    (var-set next-file-id (+ file-id u1))
    
    (ok file-id)
  )
)

;; Grant access to a file (with input validation)
(define-public (grant-access (file-id uint) (user principal) (can-read bool) (can-write bool))
  (let (
    (file-data (unwrap! (get-file-metadata file-id) ERR_FILE_NOT_FOUND))
  )
    ;; Validate inputs
    (asserts! (validate-file-id file-id) ERR_INVALID_INPUT)
    (asserts! (validate-principal user) ERR_INVALID_PRINCIPAL)
    (asserts! (not (is-eq user tx-sender)) ERR_INVALID_INPUT) ;; Can't grant to self
    
    ;; Only file owner can grant access
    (asserts! (is-eq (get owner file-data) tx-sender) ERR_UNAUTHORIZED)
    (asserts! (get is-active file-data) ERR_INVALID_INPUT) ;; File must be active
    
    (map-set file-access 
      {file-id: file-id, user: user}
      {
        can-read: can-read,
        can-write: can-write,
        granted-at: block-height,
        granted-by: tx-sender
      }
    )
    
    (ok true)
  )
)

;; Revoke access to a file
(define-public (revoke-access (file-id uint) (user principal))
  (let (
    (file-data (unwrap! (get-file-metadata file-id) ERR_FILE_NOT_FOUND))
  )
    ;; Only file owner can revoke access
    (asserts! (is-eq (get owner file-data) tx-sender) ERR_UNAUTHORIZED)
    
    (map-delete file-access {file-id: file-id, user: user})
    
    (ok true)
  )
)

;; Rotate encryption key for a file (with comprehensive validation)
(define-public (rotate-key (file-id uint) (new-public-key (buff 64)) (reason (string-ascii 100)))
  (let (
    (file-data (unwrap! (get-file-metadata file-id) ERR_FILE_NOT_FOUND))
    (old-key (get public-key file-data))
    (rotation-count (get rotation-count file-data))
  )
    ;; Validate all inputs
    (asserts! (validate-file-id file-id) ERR_INVALID_INPUT)
    (asserts! (validate-public-key new-public-key) ERR_INVALID_KEY)
    (asserts! (validate-reason reason) ERR_STRING_TOO_LONG)
    (asserts! (get is-active file-data) ERR_INVALID_INPUT) ;; File must be active
    
    ;; Only file owner or authorized key manager can rotate keys
    (asserts! (or 
      (is-eq (get owner file-data) tx-sender)
      (is-key-manager tx-sender)
    ) ERR_UNAUTHORIZED)
    
    ;; Prevent rotation to the same key
    (asserts! (not (is-eq old-key new-public-key)) ERR_INVALID_ROTATION)
    
    ;; Prevent excessive rotations (rate limiting)
    (asserts! (> block-height (+ (get last-rotated file-data) u10)) ERR_INVALID_ROTATION)
    
    ;; Store rotation history
    (map-set key-rotation-history
      {file-id: file-id, rotation-id: rotation-count}
      {
        old-key: old-key,
        new-key: new-public-key,
        rotated-at: block-height,
        rotated-by: tx-sender,
        reason: reason
      }
    )
    
    ;; Update file metadata with new key
    (map-set file-metadata file-id
      (merge file-data {
        public-key: new-public-key,
        last-rotated: block-height,
        rotation-count: (+ rotation-count u1)
      })
    )
    
    (ok true)
  )
)

;; Deactivate a file (mark as inactive)
(define-public (deactivate-file (file-id uint))
  (let (
    (file-data (unwrap! (get-file-metadata file-id) ERR_FILE_NOT_FOUND))
  )
    ;; Only file owner can deactivate
    (asserts! (is-eq (get owner file-data) tx-sender) ERR_UNAUTHORIZED)
    
    (map-set file-metadata file-id
      (merge file-data {is-active: false})
    )
    
    (ok true)
  )
)

;; Add a key manager (only contract owner, with validation)
(define-public (add-key-manager (manager principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (asserts! (validate-principal manager) ERR_INVALID_PRINCIPAL)
    (asserts! (not (is-eq manager CONTRACT_OWNER)) ERR_INVALID_INPUT) ;; Owner is already authorized
    
    (map-set key-managers manager true)
    (ok true)
  )
)

;; Remove a key manager (only contract owner)
(define-public (remove-key-manager (manager principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (map-delete key-managers manager)
    (ok true)
  )
)

;; Transfer file ownership (with validation)
(define-public (transfer-ownership (file-id uint) (new-owner principal))
  (let (
    (file-data (unwrap! (get-file-metadata file-id) ERR_FILE_NOT_FOUND))
    (old-owner-files (default-to u0 (map-get? user-file-count tx-sender)))
    (new-owner-files (default-to u0 (map-get? user-file-count new-owner)))
  )
    ;; Validate inputs
    (asserts! (validate-file-id file-id) ERR_INVALID_INPUT)
    (asserts! (validate-principal new-owner) ERR_INVALID_PRINCIPAL)
    (asserts! (not (is-eq new-owner tx-sender)) ERR_INVALID_INPUT) ;; Can't transfer to self
    (asserts! (get is-active file-data) ERR_INVALID_INPUT) ;; File must be active
    
    ;; Only current owner can transfer
    (asserts! (is-eq (get owner file-data) tx-sender) ERR_UNAUTHORIZED)
    
    ;; Check new owner doesn't exceed file limit
    (asserts! (< new-owner-files MAX_FILES_PER_USER) ERR_INVALID_INPUT)
    
    ;; Update file ownership
    (map-set file-metadata file-id
      (merge file-data {owner: new-owner})
    )
    
    ;; Update file counts
    (map-set user-file-count tx-sender (- old-owner-files u1))
    (map-set user-file-count new-owner (+ new-owner-files u1))
    
    (ok true)
  )
)