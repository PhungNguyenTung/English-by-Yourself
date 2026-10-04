# Security Specification (Phase 0: Payload-First Security TDD)

## 1. Data Invariants

1. **Global Default Deny**: Any path not explicitly matched in `firestore.rules` is unconditionally denied (`allow read, write: if false`).
2. **Verified Identity**: Write operations require an authenticated user with a verified email (`request.auth != null && request.auth.token.email_verified == true`).
3. **Admin Privileges (`isAdmin`)**: Only the bootstrapped verified owner (`phungnguyentung02@gmail.com` with `email_verified == true`) or a UID present in `/admins/{uid}` can create, update, or delete `products`, `promotions`, and `promotionRules`, or list/manage all `orders`.
4. **Relational Integrity (`promotionRules`)**: A `PromotionRule` cannot be created unless its `productId` points to an existing document in `/products/{productId}` (`exists(/databases/$(database)/documents/products/$(incoming().productId))`).
5. **PII Isolation (`orders`)**: `orders` contain customer PII (`customerName`, `phone`, `facebook`, `address`). Reading (`get` or `list`) an order is strictly restricted to the customer who placed it (`resource.data.customerId == request.auth.uid`) or `isAdmin()`.
6. **Temporal & Identity Immutability**: `createdAt` and `UpdatedAt` must equal `request.time` on creation; `updatedAt` must equal `request.time` on update; `createdAt`, `authorId`, and `customerId` are strictly immutable on update.
7. **Terminal Order State Locking**: Once an order reaches `completed` or `cancelled`, non-admin users cannot mutate it further.

## 2. The "Dirty Dozen" Payloads

1. **Unverified Admin Spoof (`products` create)**: Authenticated user with `email: "phungnguyentung02@gmail.com"` but `email_verified: false` attempts to create a product. -> `PERMISSION_DENIED`
2. **Shadow Field Injection (`orders` create)**: Customer submits valid order fields plus `"isAdmin": true`. -> `PERMISSION_DENIED`
3. **Identity Spoofing (`orders` create)**: Authenticated user `uid_A` submits an order with `customerId: "uid_B"`. -> `PERMISSION_DENIED`
4. **Cross-Tenant PII Read (`orders` get/list)**: Authenticated user `uid_A` attempts to read an order where `customerId == "uid_B"`. -> `PERMISSION_DENIED`
5. **Orphaned Promotion Rule (`promotionRules` create)**: Admin attempts to create a wholesale rule referencing non-existent `productId: "non_existent_prod"`. -> `PERMISSION_DENIED`
6. **Client Timestamp Forgery (`orders` create)**: Customer sends a forged past/future timestamp instead of `request.time` for `createdAt`. -> `PERMISSION_DENIED`
7. **Immortal Field Mutation (`orders` update)**: Customer attempts to change `createdAt` or `customerId` during an order update. -> `PERMISSION_DENIED`
8. **State Shortcutting (`orders` create)**: Customer attempts to create an order directly in `status: "completed"`. -> `PERMISSION_DENIED`
9. **Terminal State Re-opening (`orders` update)**: Customer attempts to update an order whose existing `status` is already `"cancelled"` or `"completed"`. -> `PERMISSION_DENIED`
10. **Value Poisoning (`products` update)**: Admin attempts to update `isSoldOut` with a string `"yes"` instead of a boolean. -> `PERMISSION_DENIED`
11. **Resource Exhaustion / Oversized String (`orders` create)**: Customer attempts to submit an `address` of 5,000 characters (`> 500` limit) or an empty `items` array. -> `PERMISSION_DENIED`
12. **Self-Assigned Admin Escalation (`admins` create)**: Non-admin user attempts to create `/admins/{their_uid}`. -> `PERMISSION_DENIED`
