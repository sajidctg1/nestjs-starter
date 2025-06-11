import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty, IsString } from "class-validator";

import { IsPasswordField } from "~/common/decorators/is-password.decorator";

export class ResetPasswordDto {
  @ApiProperty({ example: "abcABC@123" })
  @IsPasswordField()
  @IsNotEmpty()
  password: string;

  @ApiProperty({ example: "token" })
  @IsString()
  @IsNotEmpty()
  token: string;
}
