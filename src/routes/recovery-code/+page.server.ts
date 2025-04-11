import { getUserRecoverCode } from "$lib/server/user";
import { redirect } from "@sveltejs/kit";
import { get2FARedirect } from "$lib/server/2fa";

import type { RequestEvent } from "./$types";

export async function load(event: RequestEvent) {
	if (event.locals.session === null || event.locals.user === null) {
		return redirect(302, "/login");
	}
	if (!event.locals.user.emailVerified) {
		return redirect(302, "/verify-email");
	}
	if (!event.locals.user.registered2FA) {
		return redirect(302, "/2fa/setup");
	}
	if (!event.locals.session.twoFactorVerified) {
		return redirect(302, get2FARedirect(event.locals.user));
	}
	const recoveryCode = await getUserRecoverCode(event.locals.user.id);
	return {
		recoveryCode
	};
}
