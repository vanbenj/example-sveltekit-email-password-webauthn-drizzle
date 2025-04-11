import { db } from "./db";
import { decryptToString, encryptString } from "./encryption";
import { hashPassword } from "./password";
import { generateRandomRecoveryCode } from "./utils";
import { user, totpCredential, passkeyCredential, securityKeyCredential } from "./db/schema";
import { eq, and } from "drizzle-orm";

export function verifyUsernameInput(username: string): boolean {
	return username.length > 3 && username.length < 32 && username.trim() === username;
}

export async function createUser(email: string, username: string, password: string): Promise<User> {
	const passwordHash = await hashPassword(password);
	const recoveryCode = generateRandomRecoveryCode();
	const encryptedRecoveryCode = encryptString(recoveryCode);
	
	const result = await db.insert(user)
		.values({
			email,
			username,
			passwordHash,
			recoveryCode: Buffer.from(encryptedRecoveryCode),
			emailVerified: false
		})
		.returning({ id: user.id });
	
	if (!result.length) {
		throw new Error("Unexpected error");
	}
	
	const newUser: User = {
		id: result[0].id,
		username,
		email,
		emailVerified: false,
		registeredTOTP: false,
		registeredPasskey: false,
		registeredSecurityKey: false,
		registered2FA: false
	};
	
	return newUser;
}

export async function updateUserPassword(userId: number, password: string): Promise<void> {
	const passwordHash = await hashPassword(password);
	
	await db.update(user)
		.set({ passwordHash })
		.where(eq(user.id, userId));
}

export async function updateUserEmailAndSetEmailAsVerified(userId: number, email: string): Promise<void> {
	await db.update(user)
		.set({ email, emailVerified: true })
		.where(eq(user.id, userId));
}

export async function setUserAsEmailVerifiedIfEmailMatches(userId: number, email: string): Promise<boolean> {
	const result = await db.update(user)
		.set({ emailVerified: true })
		.where(and(eq(user.id, userId), eq(user.email, email)))
		.returning({ id: user.id });
	
	return result.length > 0;
}

export async function getUserPasswordHash(userId: number): Promise<string> {
	const result = await db.query.user.findFirst({
		where: eq(user.id, userId),
		columns: {
			passwordHash: true
		}
	});
	
	if (!result) {
		throw new Error("Invalid user ID");
	}
	
	return result.passwordHash;
}

export async function getUserRecoverCode(userId: number): Promise<string> {
	const result = await db.query.user.findFirst({
		where: eq(user.id, userId),
		columns: {
			recoveryCode: true
		}
	});
	
	if (!result) {
		throw new Error("Invalid user ID");
	}
	
	return decryptToString(result.recoveryCode);
}

export async function resetUserRecoveryCode(userId: number): Promise<string> {
	const recoveryCode = generateRandomRecoveryCode();
	const encrypted = encryptString(recoveryCode);
	
	await db.update(user)
		.set({ recoveryCode: Buffer.from(encrypted) })
		.where(eq(user.id, userId));
	
	return recoveryCode;
}

export async function getUserFromEmail(email: string): Promise<User | null> {
	const result = await db.query.user.findFirst({
		where: eq(user.email, email),
		with: {
			totpCredential: true,
			passkeyCredential: true,
			securityKeyCredential: true
		}
	});
	
	if (!result) {
		return null;
	}
	
	const userObj: User = {
		id: result.id,
		email: result.email,
		username: result.username,
		emailVerified: Boolean(result.emailVerified),
		registeredTOTP: result.totpCredential !== null,
		registeredPasskey: result.passkeyCredential !== null,
		registeredSecurityKey: result.securityKeyCredential !== null,
		registered2FA: false
	};
	
	if (userObj.registeredPasskey || userObj.registeredSecurityKey || userObj.registeredTOTP) {
		userObj.registered2FA = true;
	}
	
	return userObj;
}

export interface User {
	id: number;
	email: string;
	username: string;
	emailVerified: boolean;
	registeredTOTP: boolean;
	registeredSecurityKey: boolean;
	registeredPasskey: boolean;
	registered2FA: boolean;
}
