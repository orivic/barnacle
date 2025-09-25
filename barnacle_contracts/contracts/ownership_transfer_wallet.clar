;; Ownership Transfer Wallet Smart Contract
;; A secure wallet contract with two-step ownership transfer

;; Constants
(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_ALREADY_OWNER (err u101))
(define-constant ERR_NO_PENDING_TRANSFER (err u102))
(define-constant ERR_NOT_PENDING_OWNER (err u103))
(define-constant ERR_INVALID_PRINCIPAL (err u104))

;; Data Variables
(define-data-var current-owner principal CONTRACT_OWNER)
(define-data-var pending-owner (optional principal) none)

;; Data Maps
(define-map ownership-history
  { transfer-id: uint }
  {
    from: principal,
    to: principal,
    block-height: uint
  }
)

;; Private Variables
(define-data-var transfer-counter uint u0)

;; Read-only functions

;; Get the current owner of the contract
(define-read-only (get-owner)
  (var-get current-owner)
)

;; Get the pending owner (if any)
(define-read-only (get-pending-owner)
  (var-get pending-owner)
)

;; Check if a principal is the current owner
(define-read-only (is-owner (principal-to-check principal))
  (is-eq principal-to-check (var-get current-owner))
)

;; Get ownership transfer history by transfer ID
(define-read-only (get-transfer-history (transfer-id uint))
  (map-get? ownership-history { transfer-id: transfer-id })
)

;; Get the total number of ownership transfers
(define-read-only (get-transfer-count)
  (var-get transfer-counter)
)

;; Private functions

;; Record ownership transfer in history
(define-private (record-transfer (from principal) (to principal))
  (let ((transfer-id (+ (var-get transfer-counter) u1)))
    (map-set ownership-history
      { transfer-id: transfer-id }
      {
        from: from,
        to: to,
        block-height: block-height
      }
    )
    (var-set transfer-counter transfer-id)
    (ok transfer-id)
  )
)

;; Public functions

;; Step 1: Initiate ownership transfer
;; Only the current owner can initiate a transfer to a new owner
(define-public (transfer-ownership (new-owner principal))
  (begin
    ;; Check if caller is the current owner
    (asserts! (is-eq tx-sender (var-get current-owner)) ERR_UNAUTHORIZED)
    ;; Check if new owner is different from current owner
    (asserts! (not (is-eq new-owner (var-get current-owner))) ERR_ALREADY_OWNER)
    ;; Check if new-owner is a valid principal
    (asserts! (not (is-eq new-owner 'SP000000000000000000002Q6VF78)) ERR_INVALID_PRINCIPAL)
    
    ;; Set the pending owner
    (var-set pending-owner (some new-owner))
    
    ;; Print event for off-chain monitoring
    (print {
      event: "ownership-transfer-initiated",
      from: (var-get current-owner),
      to: new-owner,
      block-height: block-height
    })
    
    (ok true)
  )
)

;; Step 2: Accept ownership transfer
;; Only the pending owner can accept the transfer
(define-public (accept-ownership)
  (let ((pending (var-get pending-owner)))
    ;; Check if there's a pending transfer
    (asserts! (is-some pending) ERR_NO_PENDING_TRANSFER)
    ;; Check if caller is the pending owner
    (asserts! (is-eq tx-sender (unwrap-panic pending)) ERR_NOT_PENDING_OWNER)
    
    (let ((old-owner (var-get current-owner))
          (new-owner (unwrap-panic pending)))
      ;; Record the transfer in history
      (unwrap-panic (record-transfer old-owner new-owner))
      
      ;; Update the current owner
      (var-set current-owner new-owner)
      ;; Clear the pending owner
      (var-set pending-owner none)
      
      ;; Print event for off-chain monitoring
      (print {
        event: "ownership-transfer-completed",
        from: old-owner,
        to: new-owner,
        transfer-id: (var-get transfer-counter),
        block-height: block-height
      })
      
      (ok true)
    )
  )
)

;; Cancel pending ownership transfer
;; Only the current owner can cancel a pending transfer
(define-public (cancel-ownership-transfer)
  (begin
    ;; Check if caller is the current owner
    (asserts! (is-eq tx-sender (var-get current-owner)) ERR_UNAUTHORIZED)
    ;; Check if there's a pending transfer to cancel
    (asserts! (is-some (var-get pending-owner)) ERR_NO_PENDING_TRANSFER)
    
    (let ((cancelled-pending (var-get pending-owner)))
      ;; Clear the pending owner
      (var-set pending-owner none)
      
      ;; Print event for off-chain monitoring
      (print {
        event: "ownership-transfer-cancelled",
        owner: (var-get current-owner),
        cancelled-pending: cancelled-pending,
        block-height: block-height
      })
      
      (ok true)
    )
  )
)

;; Renounce ownership (permanently transfer to null/burn address)
;; This is irreversible and should be used with extreme caution
(define-public (renounce-ownership)
  (begin
    ;; Check if caller is the current owner
    (asserts! (is-eq tx-sender (var-get current-owner)) ERR_UNAUTHORIZED)
    
    (let ((old-owner (var-get current-owner))
          (burn-address 'SP000000000000000000002Q6VF78))
      ;; Record the renouncement in history
      (unwrap-panic (record-transfer old-owner burn-address))
      
      ;; Transfer ownership to burn address
      (var-set current-owner burn-address)
      ;; Clear any pending transfer
      (var-set pending-owner none)
      
      ;; Print event for off-chain monitoring
      (print {
        event: "ownership-renounced",
        former-owner: old-owner,
        transfer-id: (var-get transfer-counter),
        block-height: block-height
      })
      
      (ok true)
    )
  )
)

;; Owner-only function example
;; This demonstrates how other functions can use the ownership check
(define-public (owner-only-function)
  (begin
    ;; Check if caller is the current owner
    (asserts! (is-eq tx-sender (var-get current-owner)) ERR_UNAUTHORIZED)
    
    ;; Your owner-only logic here
    (print { event: "owner-only-function-called", caller: tx-sender })
    (ok "Function executed successfully")
  )
)