import { ApiProperty } from "@nestjs/swagger";
import {
  IsEmail,
  IsLowercase,
  IsNotEmpty,
  IsOptional,
  IsString,
} from "class-validator";

import { IsPasswordField } from "~/common/decorators/is-password.decorator";

export class UserRegisterDto {
  @ApiProperty({ example: "Jhon" })
  @IsString()
  @IsNotEmpty()
  firstName: string;

  @ApiProperty({ example: "Doe" })
  @IsString()
  @IsOptional()
  lastName?: string;

  @ApiProperty({ example: "jhon123" })
  @IsLowercase()
  @IsString()
  @IsNotEmpty()
  username: string;

  @ApiProperty({ example: "jhon@example.com" })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({ example: "abcABC@123" })
  @IsPasswordField()
  @IsNotEmpty()
  password: string;
}
