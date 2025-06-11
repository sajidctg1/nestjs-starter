type Prettify<T> = {
  [K in keyof T]: T[K];
} & {};

interface OauthResponse {
  email: string;
  firstName: string;
  lastName: string;
  accessToken: string;
}

interface AuthResponse {
  user: {
    id: number;
  };
  accessToken: string;
  refreshToken: string;
}

interface AccessTokenPayload {
  email: string;
  isTwoFactorEnabled?: boolean;
}
