import { db } from "./db";
import { encodeHexLowerCase } from "@oslojs/encoding";
import { generateRandomOTP } from "./utils";
import { sha256 } from "@oslojs/crypto/sha2";
import { passwordResetSession, type PasswordResetSession, type UserFull } from "./db/schema";
import { eq } from "drizzle-orm";

import type { RequestEvent } from "@sveltejs/kit";
import type { User } from "./user";

export async function createPasswordResetSession(token: string, userId: number, email: string): Promise<PasswordResetSession> {
	const sessionId = encodeHexLowerCase(sha256(new TextEncoder().encode(token)));
	const expiresAt = new Date(Date.now() + 1000 * 60 * 10);
	const code = generateRandomOTP();
	
	await db.insert(passwordResetSession).values({
		id: sessionId,
		userId,
		email,
		code,
		expiresAt,
		emailVerified: false,
		twoFactorVerified: false
	});
	
	return {
		id: sessionId,
		userId,
		email,
		expiresAt,
		code,
		emailVerified: false,
		twoFactorVerified: false
	};
}

export async function validatePasswordResetSessionToken(token: string): Promise<PasswordResetSessionValidationResult> {
	const sessionId = encodeHexLowerCase(sha256(new TextEncoder().encode(token)));
	
	const result = await db.query.passwordResetSession.findFirst({
		where: eq(passwordResetSession.id, sessionId),
		with: {
			user: {
				columns: {
					id: true,
					email: true,
					username: true,
					emailVerified: true
				},
				with: {
					totpCredential: {
						columns: {
							id: true
						}
					},
					passkeyCredential: {
						columns: {
							id: true
						}
					},
					securityKeyCredential: {
						columns: {
							id: true
						}
					}
				}
			}
		}
	}) as (PasswordResetSession & { user: UserFull }) | null;
	
	if (!result) {
		return { session: null, user: null };
	}
	
	const session: PasswordResetSession = {
		id: result.id,
		userId: result.userId,
		email: result.email,
		code: result.code,
		expiresAt: result.expiresAt,
		emailVerified: Boolean(result.emailVerified),
		twoFactorVerified: Boolean(result.twoFactorVerified)
	};
	
	const userData = result.user;
	const user: User = {
		id: userData.id,
		email: userData.email,
		username: userData.username,
		emailVerified: Boolean(userData.emailVerified),
		registeredTOTP: userData.totpCredential !== null,
		registeredPasskey: userData.passkeyCredential !== null,
		registeredSecurityKey: userData.securityKeyCredential !== null,
		registered2FA: userData.totpCredential !== null || userData.passkeyCredential !== null || userData.securityKeyCredential !== null
	};
	
	if (Date.now() >= session.expiresAt.getTime()) {
		await db.delete(passwordResetSession)
			.where(eq(passwordResetSession.id, session.id));
		return { session: null, user: null };
	}
	
	return { session, user };
}

export async function setPasswordResetSessionAsEmailVerified(sessionId: string): Promise<void> {
	await db.update(passwordResetSession)
		.set({ emailVerified: true })
		.where(eq(passwordResetSession.id, sessionId));
}

export async function setPasswordResetSessionAs2FAVerified(sessionId: string): Promise<void> {
	await db.update(passwordResetSession)
		.set({ twoFactorVerified: true })
		.where(eq(passwordResetSession.id, sessionId));
}

export async function invalidateUserPasswordResetSessions(userId: number): Promise<void> {
	await db.delete(passwordResetSession)
		.where(eq(passwordResetSession.userId, userId));
}

export async function validatePasswordResetSessionRequest(event: RequestEvent): Promise<PasswordResetSessionValidationResult> {
	const token = event.cookies.get("password_reset_session") ?? null;
	if (token === null) {
		return { session: null, user: null };
	}
	const result = await validatePasswordResetSessionToken(token);
	if (result.session === null) {
		deletePasswordResetSessionTokenCookie(event);
	}
	return result;
}

export function setPasswordResetSessionTokenCookie(event: RequestEvent, token: string, expiresAt: Date): void {
	event.cookies.set("password_reset_session", token, {
		expires: expiresAt,
		sameSite: "lax",
		httpOnly: true,
		path: "/",
		secure: !import.meta.env.DEV
	});
}

export function deletePasswordResetSessionTokenCookie(event: RequestEvent): void {
	event.cookies.set("password_reset_session", "", {
		maxAge: 0,
		sameSite: "lax",
		httpOnly: true,
		path: "/",
		secure: !import.meta.env.DEV
	});
}

export async function sendPasswordResetEmail(email: string, code: string): Promise<void> {
	console.log(`To ${email}: Your reset code is ${code}`);
}

export type PasswordResetSessionValidationResult =
	| { session: PasswordResetSession; user: User }
	| { session: null; user: null };
