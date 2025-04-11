import { encodeHexLowerCase } from "@oslojs/encoding";
import { db } from "./db";
import { passkeyCredential, securityKeyCredential } from "./db/schema";
import { eq, and } from "drizzle-orm";
import { Buffer } from "node:buffer";

const challengeBucket = new Set<string>();

export function createWebAuthnChallenge(): Uint8Array {
	const challenge = new Uint8Array(20);
	crypto.getRandomValues(challenge);
	const encoded = encodeHexLowerCase(challenge);
	challengeBucket.add(encoded);
	return challenge;
}

export function verifyWebAuthnChallenge(challenge: Uint8Array): boolean {
	const encoded = encodeHexLowerCase(challenge);
	return challengeBucket.delete(encoded);
}

export async function getUserPasskeyCredentials(userId: number): Promise<WebAuthnUserCredential[]> {
	const credentials = await db
		.select()
		.from(passkeyCredential)
		.where(eq(passkeyCredential.userId, userId));
	
	return credentials.map(row => ({
		id: row.id,
		userId: row.userId,
		name: row.name,
		algorithmId: row.algorithm,
		publicKey: row.publicKey
	}));
}

export async function getPasskeyCredential(credentialId: Uint8Array): Promise<WebAuthnUserCredential | null> {
	const credential = await db.query.passkeyCredential.findFirst({
		where: eq(passkeyCredential.id, Buffer.from(credentialId))
	});
	
	if (!credential) return null;
	
	return {
		...credential,
		algorithmId: credential.algorithm
	};
}

export async function getUserPasskeyCredential(userId: number, credentialId: Uint8Array): Promise<WebAuthnUserCredential | null> {
	const credential = await db.query.passkeyCredential.findFirst({
		where: and(
			eq(passkeyCredential.id, Buffer.from(credentialId)),
			eq(passkeyCredential.userId, userId)
		)
	});
	
	if (!credential) return null;
	
	return {
		...credential,
		algorithmId: credential.algorithm
	};
}

export async function createPasskeyCredential(credential: WebAuthnUserCredential): Promise<void> {
	await db.insert(passkeyCredential).values({
		id: Buffer.from(credential.id),
		userId: credential.userId,
		name: credential.name,
		algorithm: credential.algorithmId,
		publicKey: Buffer.from(credential.publicKey)
	});
}

export async function deleteUserPasskeyCredential(userId: number, credentialId: Uint8Array): Promise<boolean> {
	const result = await db
		.delete(passkeyCredential)
		.where(and(
			eq(passkeyCredential.id, Buffer.from(credentialId)),
			eq(passkeyCredential.userId, userId)
		));
	
	return result.length > 0;
}

export async function getUserSecurityKeyCredentials(userId: number): Promise<WebAuthnUserCredential[]> {
	const credentials = await db
		.select()
		.from(securityKeyCredential)
		.where(eq(securityKeyCredential.userId, userId));
	
	return credentials.map(row => ({
		id: row.id,
		userId: row.userId,
		name: row.name,
		algorithmId: row.algorithm,
		publicKey: row.publicKey
	}));
}

export async function getUserSecurityKeyCredential(userId: number, credentialId: Uint8Array): Promise<WebAuthnUserCredential | null> {
	const credential = await db.query.securityKeyCredential.findFirst({
		where: and(
			eq(securityKeyCredential.id, Buffer.from(credentialId)),
			eq(securityKeyCredential.userId, userId)
		)
	});
	
	if (!credential) return null;
	
	return {
		...credential,
		algorithmId: credential.algorithm
	};
}

export async function createSecurityKeyCredential(credential: WebAuthnUserCredential): Promise<void> {
	await db.insert(securityKeyCredential).values({
		id: Buffer.from(credential.id),
		userId: credential.userId,
		name: credential.name,
		algorithm: credential.algorithmId,
		publicKey: Buffer.from(credential.publicKey)
	});
}

export async function deleteUserSecurityKeyCredential(userId: number, credentialId: Uint8Array): Promise<boolean> {
	const result = await db
		.delete(securityKeyCredential)
		.where(and(
			eq(securityKeyCredential.id, Buffer.from(credentialId)),
			eq(securityKeyCredential.userId, userId)
		));
	
	return result.length > 0;
}

export interface WebAuthnUserCredential {
	id: Uint8Array;
	userId: number;
	name: string;
	algorithmId: number;
	publicKey: Uint8Array;
}
