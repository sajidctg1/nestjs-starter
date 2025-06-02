import { Inject, Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import {
  type Profile,
  Strategy,
  type VerifyCallback,
} from "passport-google-oauth20";

import { authConfig } from "~/configs";
import { UserService } from "~/features/user/user.service";

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, "google") {
  constructor(
    @Inject(authConfig.KEY) authConfigs: Configs["auth"],
    private userService: UserService
  ) {
    super({
      clientID: authConfigs.googleClientId,
      clientSecret: authConfigs.googleClientSecret,
      callbackURL: authConfigs.googleCallbackUrl,
      scope: ["email", "profile"],
    });
  }

  async validate(
    _accessToken: string,
    _refreshToken: string,
    profile: Profile,
    done: VerifyCallback
  ): Promise<any> {
    const { id, name, emails, photos, username } = profile;
    const email = emails![0]!.value;

    // Check if the user already exists in database
    const existingUser = await this.userService.findByEmail(email);
    if (existingUser) {
      // If the user exists, return the user object
      done(undefined, existingUser);
    } else {
      // If the user doesn't exist, create a new user
      const newAccont = await this.userService.createOauthAccount({
        user: {
          email: email,
          firstName: name?.givenName ?? "",
          lastName: name?.familyName ?? "",
          username: username ?? email,
          avatar: photos?.[0]?.value,
          isVerified: true,
        },
        account: {
          provider: "google",
          providerAccountId: id,
        },
      });

      done(undefined, newAccont.user);
    }
  }
}
