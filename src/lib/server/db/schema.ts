import { pgTable, text, integer, index, customType, timestamp, serial, boolean } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import type { Buffer } from 'node:buffer';

const bytea = customType<{ data: Buffer; notNull: false; default: false }>({
	dataType() {
	  return "bytea";
	},
});

export const user = pgTable(
	'user',
	{
		id: serial('id').primaryKey(),
		email: text('email').notNull().unique(),
		username: text('username').notNull(),
		passwordHash: text('password_hash').notNull(),
		emailVerified: boolean('email_verified').notNull().default(false),
		totpKey: bytea('totp_key'),
		recoveryCode: bytea('recovery_code').notNull()
	},
	(table) => [
		index('email_index').on(table.email)
	]
);

export const session = pgTable('session', {
	id: text('id').primaryKey(),
	userId: integer('user_id')
		.notNull()
		.references(() => user.id),
	expiresAt: timestamp('expires_at', { withTimezone: true, mode: 'date' }).notNull(),
	twoFactorVerified: boolean('two_factor_verified').notNull().default(false)
});

export const emailVerificationRequest = pgTable('email_verification_request', {
	id: text('id').primaryKey(),
	userId: integer('user_id')
		.notNull()
		.references(() => user.id),
	email: text('email').notNull(),
	code: text('code').notNull(),
	expiresAt: timestamp('expires_at', { withTimezone: true, mode: 'date' }).notNull(),
});

export const passwordResetSession = pgTable('password_reset_session', {
	id: text('id').primaryKey(),
	userId: integer('user_id')
		.notNull()
		.references(() => user.id),
	email: text('email').notNull(),
	code: text('code').notNull(),
	expiresAt: timestamp('expires_at', { withTimezone: true, mode: 'date' }).notNull(),
	emailVerified: boolean('email_verified').notNull().default(false),
	twoFactorVerified: boolean('two_factor_verified').notNull().default(false)
});

export const totpCredential = pgTable('totp_credential', {
	id: serial('id').primaryKey(),
	userId: integer('user_id')
		.notNull()
		.unique()
		.references(() => user.id),
	key: bytea('key').notNull()
});

export const passkeyCredential = pgTable('passkey_credential', {
	id: bytea('id').primaryKey(),
	userId: integer('user_id')
		.notNull()
		.references(() => user.id),
	name: text('name').notNull(),
	algorithm: integer('algorithm').notNull(),
	publicKey: bytea('public_key').notNull()
});

export const securityKeyCredential = pgTable('security_key_credential', {
	id: bytea('id').primaryKey(),
	userId: integer('user_id')
		.notNull()
		.references(() => user.id),
	name: text('name').notNull(),
	algorithm: integer('algorithm').notNull(),
	publicKey: bytea('public_key').notNull()
});

export const userRelations = relations(user, ({ many, one }) => ({
	sessions: many(session),
	emailVerificationRequests: many(emailVerificationRequest),
	passwordResetSessions: many(passwordResetSession),
	totpCredential: one(totpCredential),
	passkeyCredential: one(passkeyCredential),
	securityKeyCredential: one(securityKeyCredential)
}));

export const sessionRelations = relations(session, ({ one }) => ({
	user: one(user, {
		fields: [session.userId],
		references: [user.id]
	})
}));

export const emailVerificationRequestRelations = relations(emailVerificationRequest, ({ one }) => ({
	user: one(user, {
		fields: [emailVerificationRequest.userId],
		references: [user.id]
	})
}));

export const passwordResetSessionRelations = relations(passwordResetSession, ({ one }) => ({
	user: one(user, {
		fields: [passwordResetSession.userId],
		references: [user.id]
	})
}));

export const totpCredentialRelations = relations(totpCredential, ({ one }) => ({
	user: one(user, {
		fields: [totpCredential.userId],
		references: [user.id]
	})
}));

export const passkeyCredentialRelations = relations(passkeyCredential, ({ one }) => ({
	user: one(user, {
		fields: [passkeyCredential.userId],
		references: [user.id]
	})
}));

export const securityKeyCredentialRelations = relations(securityKeyCredential, ({ one }) => ({
	user: one(user, {
		fields: [securityKeyCredential.userId],
		references: [user.id]
	})
}));

export type UserFull = typeof user.$inferSelect & {
	totpCredential: typeof totpCredential.$inferSelect | null;
	passkeyCredential: typeof passkeyCredential.$inferSelect | null;
	securityKeyCredential: typeof securityKeyCredential.$inferSelect | null;
};

export type Session = typeof session.$inferSelect;
export type EmailVerificationRequest = typeof emailVerificationRequest.$inferSelect;
export type PasswordResetSession = typeof passwordResetSession.$inferSelect;
export type TotpCredential = typeof totpCredential.$inferSelect;
export type PasskeyCredential = typeof passkeyCredential.$inferSelect;
export type SecurityKeyCredential = typeof securityKeyCredential.$inferSelect;
