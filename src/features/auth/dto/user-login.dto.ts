import { ApiProperty } from "@nestjs/swagger";
import { IsBoolean, IsEmail, IsNotEmpty, IsOptional } from "class-validator";

import { IsPasswordField } from "~/common/decorators/is-password.decorator";

export class UserLoginDto {
  @ApiProperty({ example: "jhon@example.com" })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({ example: "abcABC@123" })
  @IsPasswordField()
  @IsNotEmpty()
  password: string;

  @ApiProperty({ example: false })
  @IsBoolean()
  @IsOptional()
  remember = false;
}
