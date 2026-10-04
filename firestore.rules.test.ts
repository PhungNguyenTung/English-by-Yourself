/**
 * Security Rules Verification Suite for Dirty Dozen Payloads
 * Verifies all 12 adversarial payloads specified in security_spec.md return PERMISSION_DENIED.
 */

export interface DirtyDozenTestCase {
  id: number;
  name: string;
  collection: string;
  operation: 'get' | 'list' | 'create' | 'update' | 'delete';
  auth: { uid: string; email: string; email_verified: boolean } | null;
  payload?: Record<string, unknown>;
  expectedResult: 'PERMISSION_DENIED';
}

export const DIRTY_DOZEN_TESTS: DirtyDozenTestCase[] = [
  {
    id: 1,
    name: 'Unverified Admin Spoof on Product Creation',
    collection: 'products/prod_1',
    operation: 'create',
    auth: { uid: 'spoof_uid', email: 'phungnguyentung02@gmail.com', email_verified: false },
    payload: {
      name: 'Bó hoa hồng sáp',
      price: 150000,
      imageUrl: '',
      isSoldOut: false,
      visibility: 'public',
      authorId: 'spoof_uid',
    },
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 2,
    name: 'Shadow Field Injection on Order Creation',
    collection: 'orders/order_1',
    operation: 'create',
    auth: { uid: 'user_a', email: 'usera@example.com', email_verified: true },
    payload: {
      customerId: 'user_a',
      customerName: 'Nguyen Van A',
      phone: '0987654321',
      facebook: '',
      address: '12A1 THPT Ngo Quyen',
      items: [{ productId: 'prod_1', name: 'Hoa', quantity: 1, unitPrice: 100000, originalUnitPrice: 100000, lineTotal: 100000 }],
      originalTotal: 100000,
      discountAmount: 0,
      finalTotal: 100000,
      status: 'new',
      isVerifiedAdmin: true,
    },
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 3,
    name: 'Identity Spoofing on Order Creation',
    collection: 'orders/order_2',
    operation: 'create',
    auth: { uid: 'user_a', email: 'usera@example.com', email_verified: true },
    payload: {
      customerId: 'user_b',
      customerName: 'Nguyen Van A',
      phone: '0987654321',
      facebook: '',
      address: '12A1 THPT Ngo Quyen',
      items: [{ productId: 'prod_1', name: 'Hoa', quantity: 1, unitPrice: 100000, originalUnitPrice: 100000, lineTotal: 100000 }],
      originalTotal: 100000,
      discountAmount: 0,
      finalTotal: 100000,
      status: 'new',
    },
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 4,
    name: 'Cross-Tenant PII Read on Orders',
    collection: 'orders/order_of_user_b',
    operation: 'get',
    auth: { uid: 'user_a', email: 'usera@example.com', email_verified: true },
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 5,
    name: 'Orphaned Promotion Rule Creation',
    collection: 'promotionRules/rule_orphan',
    operation: 'create',
    auth: { uid: 'admin_uid', email: 'phungnguyentung02@gmail.com', email_verified: true },
    payload: {
      productId: 'non_existent_product_id',
      minQty: 5,
      price: 120000,
      visibility: 'public',
      authorId: 'admin_uid',
    },
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 6,
    name: 'Client Timestamp Forgery on Order Creation',
    collection: 'orders/order_3',
    operation: 'create',
    auth: { uid: 'user_a', email: 'usera@example.com', email_verified: true },
    payload: {
      customerId: 'user_a',
      customerName: 'Nguyen Van A',
      phone: '0987654321',
      facebook: '',
      address: '12A1',
      items: [{ productId: 'prod_1', name: 'Hoa', quantity: 1, unitPrice: 100000, originalUnitPrice: 100000, lineTotal: 100000 }],
      originalTotal: 100000,
      discountAmount: 0,
      finalTotal: 100000,
      status: 'new',
      createdAt: 1700000000000,
      updatedAt: 1700000000000,
    },
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 7,
    name: 'Immortal Field Mutation on Order Update',
    collection: 'orders/order_1',
    operation: 'update',
    auth: { uid: 'user_a', email: 'usera@example.com', email_verified: true },
    payload: {
      customerId: 'user_b',
      status: 'cancelled',
    },
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 8,
    name: 'State Shortcutting on Order Creation',
    collection: 'orders/order_4',
    operation: 'create',
    auth: { uid: 'user_a', email: 'usera@example.com', email_verified: true },
    payload: {
      customerId: 'user_a',
      customerName: 'Nguyen Van A',
      phone: '0987654321',
      facebook: '',
      address: '12A1',
      items: [{ productId: 'prod_1', name: 'Hoa', quantity: 1, unitPrice: 100000, originalUnitPrice: 100000, lineTotal: 100000 }],
      originalTotal: 100000,
      discountAmount: 0,
      finalTotal: 100000,
      status: 'completed',
    },
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 9,
    name: 'Terminal State Re-opening on Order Update',
    collection: 'orders/order_completed',
    operation: 'update',
    auth: { uid: 'user_a', email: 'usera@example.com', email_verified: true },
    payload: {
      status: 'new',
    },
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 10,
    name: 'Value Poisoning on Product Update',
    collection: 'products/prod_1',
    operation: 'update',
    auth: { uid: 'admin_uid', email: 'phungnguyentung02@gmail.com', email_verified: true },
    payload: {
      isSoldOut: 'yes_sold_out',
    },
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 11,
    name: 'Oversized String / Empty Items Array on Order Creation',
    collection: 'orders/order_5',
    operation: 'create',
    auth: { uid: 'user_a', email: 'usera@example.com', email_verified: true },
    payload: {
      customerId: 'user_a',
      customerName: 'Nguyen Van A',
      phone: '0987654321',
      facebook: '',
      address: 'A'.repeat(600),
      items: [],
      originalTotal: 0,
      discountAmount: 0,
      finalTotal: 0,
      status: 'new',
    },
    expectedResult: 'PERMISSION_DENIED',
  },
  {
    id: 12,
    name: 'Self-Assigned Admin Escalation',
    collection: 'admins/user_a',
    operation: 'create',
    auth: { uid: 'user_a', email: 'usera@example.com', email_verified: true },
    payload: {
      email: 'usera@example.com',
    },
    expectedResult: 'PERMISSION_DENIED',
  },
];
