import { env } from "@/lib/env";

type HCaptchaVerifyResponse = {
  success: boolean;
  "error-codes"?: string[];
};

export function isCaptchaEnabled(): boolean {
  return Boolean(env.HCAPTCHA_SECRET);
}

export async function verifyCaptcha(
  token: string | null | undefined,
  remoteIp?: string,
): Promise<boolean> {
  if (!isCaptchaEnabled()) {
    return true;
  }

  if (!token) {
    return false;
  }

  const params = new URLSearchParams({
    secret: env.HCAPTCHA_SECRET as string,
    response: token,
  });

  if (remoteIp) {
    params.set("remoteip", remoteIp);
  }

  try {
    const response = await fetch("https://api.hcaptcha.com/siteverify", {
      method: "POST",
      body: params,
      cache: "no-store",
    });

    if (!response.ok) {
      return false;
    }

    const data = (await response.json()) as HCaptchaVerifyResponse;
    return data.success === true;
  } catch (err) {
    console.error("Failed to verify hCaptcha token.", err);
    return false;
  }
}
