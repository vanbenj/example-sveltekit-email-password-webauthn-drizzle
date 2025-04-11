import { db } from "./db";
import { decrypt, encrypt } from "./encryption";
import { ExpiringTokenBucket, RefillingTokenBucket } from "./rate-limit";
import { eq } from "drizzle-orm";
import { totpCredential } from "./db/schema";
import { Buffer } from "node:buffer";

export const totpBucket = new ExpiringTokenBucket<number>(5, 60 * 30);
export const totpUpdateBucket = new RefillingTokenBucket<number>(3, 60 * 10);

export async function getUserTOTPKey(userId: number): Promise<Uint8Array | null> {
	const result = await db.query.totpCredential.findFirst({
		where: eq(totpCredential.userId, userId),
		columns: {
			key: true
		}
	});

	if (!result) {
		throw new Error("Invalid user ID");
	}

	return result.key ? decrypt(result.key) : null;
}

export async function updateUserTOTPKey(userId: number, key: Uint8Array): Promise<void> {
	const encrypted = encrypt(key);
	const buffer = Buffer.from(encrypted);
	
	await db.transaction(async (tx) => {
		await tx.delete(totpCredential).where(eq(totpCredential.userId, userId));
		await tx.insert(totpCredential).values({
			userId,
			key: buffer
		});
	});
}

export async function deleteUserTOTPKey(userId: number): Promise<void> {
	await db.delete(totpCredential).where(eq(totpCredential.userId, userId));
}
