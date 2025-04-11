import { db } from "./db";
import { user } from "./db/schema";
import { eq } from "drizzle-orm";

export function verifyEmailInput(email: string): boolean {
	return /^.+@.+\..+$/.test(email) && email.length < 256;
}

export async function checkEmailAvailability(email: string): Promise<boolean> {
	const result = await db.query.user.findFirst({
		where: eq(user.email, email),
		columns: {
			id: true
		}
	});
	
	return result === undefined;
}
