import { db } from "./db";
import { encodeBase32LowerCaseNoPadding, encodeHexLowerCase } from "@oslojs/encoding";
import { sha256 } from "@oslojs/crypto/sha2";
import { session, user } from "./db/schema";
import { eq } from "drizzle-orm";

import type { User } from "./user";
import type { RequestEvent } from "@sveltejs/kit";

export async function validateSessionToken(token: string): Promise<SessionValidationResult> {
	const sessionId = encodeHexLowerCase(sha256(new TextEncoder().encode(token)));
	
	const result = await db.query.session.findFirst({
		where: eq(session.id, sessionId),
		with: {
			user: {
				with: {
					totpCredential: true,
					passkeyCredential: true,
					securityKeyCredential: true
				}
			}
		}
	});

	if (!result) {
		return { session: null, user: null };
	}
	
	const sessionObj: Session = {
		id: result.id,
		userId: result.userId,
		expiresAt: result.expiresAt,
		twoFactorVerified: Boolean(result.twoFactorVerified)
	};
	
	const userData = result.user;
	const userObj: User = {
		id: userData.id,
		email: userData.email,
		username: userData.username,
		emailVerified: Boolean(userData.emailVerified),
		registeredTOTP: userData.totpCredential !== null,
		registeredPasskey: userData.passkeyCredential !== null,
		registeredSecurityKey: userData.securityKeyCredential !== null,
		registered2FA: userData.totpCredential !== null || userData.passkeyCredential !== null || userData.securityKeyCredential !== null
	};
	
	if (Date.now() >= sessionObj.expiresAt.getTime()) {
		await db.delete(session)
			.where(eq(session.id, sessionObj.id));
		return { session: null, user: null };
	}
	
	if (Date.now() >= sessionObj.expiresAt.getTime() - 1000 * 60 * 60 * 24 * 15) {
		sessionObj.expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30);
		await db.update(session)
			.set({ expiresAt: sessionObj.expiresAt })
			.where(eq(session.id, sessionObj.id));
	}
	
	return { session: sessionObj, user: userObj };
}

export async function invalidateSession(sessionId: string): Promise<void> {
	await db.delete(session)
		.where(eq(session.id, sessionId));
}

export async function invalidateUserSessions(userId: number): Promise<void> {
	await db.delete(session)
		.where(eq(session.userId, userId));
}

export function setSessionTokenCookie(event: RequestEvent, token: string, expiresAt: Date): void {
	event.cookies.set("session", token, {
		httpOnly: true,
		path: "/",
		secure: import.meta.env.PROD,
		sameSite: "lax",
		expires: expiresAt
	});
}

export function deleteSessionTokenCookie(event: RequestEvent): void {
	event.cookies.set("session", "", {
		httpOnly: true,
		path: "/",
		secure: import.meta.env.PROD,
		sameSite: "lax",
		maxAge: 0
	});
}

export function generateSessionToken(): string {
	const tokenBytes = new Uint8Array(20);
	crypto.getRandomValues(tokenBytes);
	const token = encodeBase32LowerCaseNoPadding(tokenBytes);
	return token;
}

export async function createSession(token: string, userId: number, flags: SessionFlags): Promise<Session> {
	const sessionId = encodeHexLowerCase(sha256(new TextEncoder().encode(token)));
	const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30);
	
	await db.insert(session).values({
		id: sessionId,
		userId,
		expiresAt,
		twoFactorVerified: flags.twoFactorVerified
	});
	
	return {
		id: sessionId,
		userId,
		expiresAt,
		twoFactorVerified: flags.twoFactorVerified
	};
}

export async function setSessionAs2FAVerified(sessionId: string): Promise<void> {
	await db.update(session)
		.set({ twoFactorVerified: true })
		.where(eq(session.id, sessionId));
}

export interface SessionFlags {
	twoFactorVerified: boolean;
}

export interface Session extends SessionFlags {
	id: string;
	expiresAt: Date;
	userId: number;
}

type SessionValidationResult = { session: Session; user: User } | { session: null; user: null };
