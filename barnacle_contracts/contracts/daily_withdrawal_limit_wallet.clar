;; Daily Withdrawal Limit Wallet Contract
;; A smart contract that limits daily withdrawals per user

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-insufficient-balance (err u101))
(define-constant err-daily-limit-exceeded (err u102))
(define-constant err-invalid-amount (err u103))
(define-constant err-transfer-failed (err u104))

;; Default daily limit (in microSTX, 1 STX = 1,000,000 microSTX)
(define-constant default-daily-limit u10000000) ;; 10 STX

;; Data Variables
(define-data-var contract-balance uint u0)

;; Data Maps
;; Track user balances
(define-map user-balances principal uint)

;; Track daily withdrawal data: amount withdrawn and last withdrawal date
(define-map daily-withdrawals 
  principal 
  {
    amount-withdrawn: uint,
    last-withdrawal-day: uint,
    daily-limit: uint
  }
)

;; Private Functions

;; Get current day (block height divided by 144 blocks per day approximately)
(define-private (get-current-day)
  (/ block-height u144)
)

;; Check if it's a new day for the user
(define-private (is-new-day (user principal))
  (let ((withdrawal-data (default-to 
                           {amount-withdrawn: u0, last-withdrawal-day: u0, daily-limit: default-daily-limit}
                           (map-get? daily-withdrawals user))))
    (> (get-current-day) (get last-withdrawal-day withdrawal-data))
  )
)

;; Reset daily withdrawal counter if it's a new day
(define-private (reset-daily-counter-if-needed (user principal))
  (let ((withdrawal-data (default-to 
                           {amount-withdrawn: u0, last-withdrawal-day: u0, daily-limit: default-daily-limit}
                           (map-get? daily-withdrawals user))))
    (if (is-new-day user)
        (map-set daily-withdrawals user 
          (merge withdrawal-data {amount-withdrawn: u0, last-withdrawal-day: (get-current-day)}))
        true
    )
  )
)

;; Public Functions

;; Deposit STX into the wallet
(define-public (deposit (amount uint))
  (begin
    (asserts! (> amount u0) err-invalid-amount)
    (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
    (var-set contract-balance (+ (var-get contract-balance) amount))
    (map-set user-balances tx-sender 
      (+ (default-to u0 (map-get? user-balances tx-sender)) amount))
    (ok amount)
  )
)

;; Withdraw STX from the wallet (subject to daily limits)
(define-public (withdraw (amount uint))
  (let (
    (user-balance (default-to u0 (map-get? user-balances tx-sender)))
    (withdrawal-data (default-to 
                       {amount-withdrawn: u0, last-withdrawal-day: u0, daily-limit: default-daily-limit}
                       (map-get? daily-withdrawals tx-sender)))
  )
    (begin
      ;; Validate amount
      (asserts! (> amount u0) err-invalid-amount)
      (asserts! (<= amount user-balance) err-insufficient-balance)
      
      ;; Reset daily counter if needed
      (reset-daily-counter-if-needed tx-sender)
      
      ;; Get updated withdrawal data after potential reset
      (let ((updated-withdrawal-data (default-to 
                                       {amount-withdrawn: u0, last-withdrawal-day: (get-current-day), daily-limit: default-daily-limit}
                                       (map-get? daily-withdrawals tx-sender))))
        (begin
          ;; Check daily limit
          (asserts! (<= (+ (get amount-withdrawn updated-withdrawal-data) amount) 
                       (get daily-limit updated-withdrawal-data)) 
                   err-daily-limit-exceeded)
          
          ;; Execute withdrawal
          (try! (as-contract (stx-transfer? amount tx-sender tx-sender)))
          
          ;; Update balances and withdrawal tracking
          (var-set contract-balance (- (var-get contract-balance) amount))
          (map-set user-balances tx-sender (- user-balance amount))
          (map-set daily-withdrawals tx-sender 
            (merge updated-withdrawal-data 
              {
                amount-withdrawn: (+ (get amount-withdrawn updated-withdrawal-data) amount),
                last-withdrawal-day: (get-current-day)
              }
            )
          )
          
          (ok amount)
        )
      )
    )
  )
)

;; Set custom daily limit for a user (only contract owner can call this)
(define-public (set-daily-limit (user principal) (new-limit uint))
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (asserts! (> new-limit u0) err-invalid-amount)
    (let ((withdrawal-data (default-to 
                             {amount-withdrawn: u0, last-withdrawal-day: u0, daily-limit: default-daily-limit}
                             (map-get? daily-withdrawals user))))
      (map-set daily-withdrawals user 
        (merge withdrawal-data {daily-limit: new-limit}))
      (ok new-limit)
    )
  )
)

;; Read-only Functions

;; Get user's current balance
(define-read-only (get-user-balance (user principal))
  (default-to u0 (map-get? user-balances user))
)

;; Get user's daily withdrawal information
(define-read-only (get-daily-withdrawal-info (user principal))
  (let ((withdrawal-data (default-to 
                           {amount-withdrawn: u0, last-withdrawal-day: u0, daily-limit: default-daily-limit}
                           (map-get? daily-withdrawals user))))
    {
      amount-withdrawn-today: (if (is-new-day user) u0 (get amount-withdrawn withdrawal-data)),
      daily-limit: (get daily-limit withdrawal-data),
      remaining-limit: (if (is-new-day user) 
                        (get daily-limit withdrawal-data)
                        (- (get daily-limit withdrawal-data) (get amount-withdrawn withdrawal-data))),
      last-withdrawal-day: (get last-withdrawal-day withdrawal-data),
      current-day: (get-current-day)
    }
  )
)

;; Get remaining withdrawal limit for today
(define-read-only (get-remaining-daily-limit (user principal))
  (let ((withdrawal-info (get-daily-withdrawal-info user)))
    (get remaining-limit withdrawal-info)
  )
)

;; Get total contract balance
(define-read-only (get-contract-balance)
  (var-get contract-balance)
)

;; Get contract owner
(define-read-only (get-contract-owner)
  contract-owner
)