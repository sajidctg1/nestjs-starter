import { IsNotEmpty, IsNumber, IsString } from "class-validator";

import { CreateUserDto } from "./create-user.dto";

export class CreateAccountDto {
  @IsNotEmpty()
  @IsNumber()
  userId: number;

  @IsNotEmpty()
  @IsString()
  provider: string;

  @IsNotEmpty()
  @IsString()
  providerAccountId: string;
}

export type CreateOauthAccountDto = {
  user: CreateUserDto;
  account: Omit<CreateAccountDto, "userId">;
};
