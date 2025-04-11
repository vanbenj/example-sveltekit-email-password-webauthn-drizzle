import { db } from "./db";
import { generateRandomRecoveryCode } from "./utils";
import { ExpiringTokenBucket } from "./rate-limit";
import { decryptToString, encryptString } from "./encryption";
import { user, session, totpCredential, passkeyCredential, securityKeyCredential } from "./db/schema";
import { eq } from "drizzle-orm";
import { Buffer } from "node:buffer";

import type { User } from "./user";

export const recoveryCodeBucket = new ExpiringTokenBucket<number>(3, 60 * 60);

export async function resetUser2FAWithRecoveryCode(userId: number, recoveryCode: string): Promise<boolean> {
	await db.transaction(async (tx) => {
		const userRecord = await db.select({ recoveryCode: user.recoveryCode })
			.from(user)
			.where(eq(user.id, userId))
			.limit(1)
			.for('update');

		if (userRecord.length === 0) {
			return false;
		}

		const userRecoveryCode = decryptToString(userRecord[0].recoveryCode);
		if (recoveryCode !== userRecoveryCode) {
			return false;
		}

		const newRecoveryCode = generateRandomRecoveryCode();
		const encryptedNewRecoveryCode = encryptString(newRecoveryCode);

		// Update user's recovery code
		const result = await tx.update(user)
			.set({ recoveryCode: Buffer.from(encryptedNewRecoveryCode) })
			.where(eq(user.id, userId))
			.returning();

		if (result.length === 0) {
			throw new Error("Failed to update recovery code");
		}

		// Reset 2FA verification status
		await tx.update(session)
			.set({ twoFactorVerified: false })
			.where(eq(session.userId, userId));

		// Delete all 2FA credentials
		await tx.delete(totpCredential)
			.where(eq(totpCredential.userId, userId));
		await tx.delete(passkeyCredential)
			.where(eq(passkeyCredential.userId, userId));
		await tx.delete(securityKeyCredential)
			.where(eq(securityKeyCredential.userId, userId));
	});

	return true;
}

export function get2FARedirect(user: User): string {
	if (user.registeredPasskey) {
		return "/2fa/passkey";
	}
	if (user.registeredSecurityKey) {
		return "/2fa/security-key";
	}
	if (user.registeredTOTP) {
		return "/2fa/totp";
	}
	return "/2fa/setup";
}

export function getPasswordReset2FARedirect(user: User): string {
	if (user.registeredPasskey) {
		return "/reset-password/2fa/passkey";
	}
	if (user.registeredSecurityKey) {
		return "/reset-password/2fa/security-key";
	}
	if (user.registeredTOTP) {
		return "/reset-password/2fa/totp";
	}
	return "/2fa/setup";
}
