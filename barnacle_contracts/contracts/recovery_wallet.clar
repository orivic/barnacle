;; Recovery Wallet Smart Contract
;; Allows recovery by trusted address with time delay

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-not-authorized (err u101))
(define-constant err-recovery-pending (err u102))
(define-constant err-no-recovery-pending (err u103))
(define-constant err-recovery-too-early (err u104))
(define-constant err-invalid-recovery-address (err u105))
(define-constant err-insufficient-balance (err u106))

;; Recovery delay in blocks (approximately 24 hours at 10 min/block)
(define-constant recovery-delay u144)

;; Data Variables
(define-data-var wallet-owner principal contract-owner)
(define-data-var recovery-address (optional principal) none)
(define-data-var recovery-initiated-at (optional uint) none)
(define-data-var pending-new-owner (optional principal) none)

;; Maps
(define-map authorized-recovery-addresses principal bool)

;; Read-only functions
(define-read-only (get-wallet-owner)
  (var-get wallet-owner))

(define-read-only (get-recovery-address)
  (var-get recovery-address))

(define-read-only (get-recovery-status)
  {
    recovery-initiated-at: (var-get recovery-initiated-at),
    pending-new-owner: (var-get pending-new-owner),
    current-block: block-height,
    recovery-ready: (match (var-get recovery-initiated-at)
      initiated-at (>= block-height (+ initiated-at recovery-delay))
      false)
  })

(define-read-only (is-recovery-authorized (recovery-addr principal))
  (default-to false (map-get? authorized-recovery-addresses recovery-addr)))

(define-read-only (get-wallet-balance)
  (stx-get-balance (as-contract tx-sender)))

;; Public functions

;; Set recovery address (only wallet owner)
(define-public (set-recovery-address (new-recovery-addr principal))
  (begin
    (asserts! (is-eq tx-sender (var-get wallet-owner)) err-owner-only)
    (asserts! (not (is-eq new-recovery-addr (var-get wallet-owner))) err-invalid-recovery-address)
    (var-set recovery-address (some new-recovery-addr))
    (map-set authorized-recovery-addresses new-recovery-addr true)
    (ok true)))

;; Remove recovery address (only wallet owner)
(define-public (remove-recovery-address)
  (begin
    (asserts! (is-eq tx-sender (var-get wallet-owner)) err-owner-only)
    (match (var-get recovery-address)
      recovery-addr (map-delete authorized-recovery-addresses recovery-addr)
      true)
    (var-set recovery-address none)
    (ok true)))

;; Initiate recovery process (only authorized recovery address)
(define-public (initiate-recovery (new-owner principal))
  (begin
    (asserts! (is-some (var-get recovery-address)) err-not-authorized)
    (asserts! (is-recovery-authorized tx-sender) err-not-authorized)
    (asserts! (is-none (var-get recovery-initiated-at)) err-recovery-pending)
    (asserts! (not (is-eq new-owner (var-get wallet-owner))) err-invalid-recovery-address)
    
    (var-set recovery-initiated-at (some block-height))
    (var-set pending-new-owner (some new-owner))
    (ok true)))

;; Cancel recovery (only wallet owner)
(define-public (cancel-recovery)
  (begin
    (asserts! (is-eq tx-sender (var-get wallet-owner)) err-owner-only)
    (asserts! (is-some (var-get recovery-initiated-at)) err-no-recovery-pending)
    
    (var-set recovery-initiated-at none)
    (var-set pending-new-owner none)
    (ok true)))

;; Complete recovery (only authorized recovery address, after delay)
(define-public (complete-recovery)
  (let (
    (initiated-at (unwrap! (var-get recovery-initiated-at) err-no-recovery-pending))
    (new-owner (unwrap! (var-get pending-new-owner) err-no-recovery-pending))
  )
    (asserts! (is-recovery-authorized tx-sender) err-not-authorized)
    (asserts! (>= block-height (+ initiated-at recovery-delay)) err-recovery-too-early)
    
    ;; Transfer ownership
    (var-set wallet-owner new-owner)
    
    ;; Clear recovery state
    (var-set recovery-initiated-at none)
    (var-set pending-new-owner none)
    
    ;; Remove old recovery address authorization
    (match (var-get recovery-address)
      recovery-addr (map-delete authorized-recovery-addresses recovery-addr)
      true)
    (var-set recovery-address none)
    
    (ok true)))

;; Deposit STX to wallet
(define-public (deposit (amount uint))
  (stx-transfer? amount tx-sender (as-contract tx-sender)))

;; Withdraw STX (only wallet owner)
(define-public (withdraw (amount uint) (recipient principal))
  (begin
    (asserts! (is-eq tx-sender (var-get wallet-owner)) err-owner-only)
    (asserts! (<= amount (stx-get-balance (as-contract tx-sender))) err-insufficient-balance)
    (as-contract (stx-transfer? amount tx-sender recipient))))

;; Emergency withdraw all funds (only wallet owner)
(define-public (emergency-withdraw (recipient principal))
  (let ((balance (stx-get-balance (as-contract tx-sender))))
    (asserts! (is-eq tx-sender (var-get wallet-owner)) err-owner-only)
    (asserts! (> balance u0) err-insufficient-balance)
    (as-contract (stx-transfer? balance tx-sender recipient))))

;; Transfer ownership (only wallet owner, immediate)
(define-public (transfer-ownership (new-owner principal))
  (begin
    (asserts! (is-eq tx-sender (var-get wallet-owner)) err-owner-only)
    (asserts! (not (is-eq new-owner (var-get wallet-owner))) err-invalid-recovery-address)
    
    ;; Cancel any pending recovery
    (var-set recovery-initiated-at none)
    (var-set pending-new-owner none)
    
    ;; Transfer ownership
    (var-set wallet-owner new-owner)
    (ok true)))

;; Get contract info
(define-read-only (get-contract-info)
  {
    wallet-owner: (var-get wallet-owner),
    recovery-address: (var-get recovery-address),
    balance: (stx-get-balance (as-contract tx-sender)),
    recovery-delay-blocks: recovery-delay,
    contract-address: (as-contract tx-sender)
  })