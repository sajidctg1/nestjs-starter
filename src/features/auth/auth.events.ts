export class UserRegisteredEvent {
  id: number;

  email: string;

  token: string;

  constructor(items: UserRegisteredEvent) {
    Object.assign(this, items);
  }
}

export class ResendVerifyLinkEvent {
  id: number;

  email: string;

  token: string;

  constructor(items: ResendVerifyLinkEvent) {
    Object.assign(this, items);
  }
}

export class SendPasswordResetLinkEvent {
  username: string;

  email: string;

  token: string;

  constructor(items: SendPasswordResetLinkEvent) {
    Object.assign(this, items);
  }
}
