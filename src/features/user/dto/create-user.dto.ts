import { ApiProperty } from "@nestjs/swagger";
import {
  IsBoolean,
  IsEmail,
  IsLowercase,
  IsNotEmpty,
  IsNumber,
  IsOptional,
  IsString,
} from "class-validator";

import { IsPasswordField } from "~/common/decorators/is-password.decorator";

export class CreateUserDto {
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
  @IsOptional()
  password?: string;

  @ApiProperty()
  @IsString()
  @IsOptional()
  avatar?: string;

  @ApiProperty({ example: false })
  @IsBoolean()
  @IsOptional()
  isVerified?: boolean;

  @ApiProperty({ example: false })
  @IsBoolean()
  @IsOptional()
  isTwoFAEnabled?: boolean;

  @IsPasswordField()
  @IsOptional()
  twoFASecret?: string;

  @ApiProperty({ example: 1 })
  @IsNumber()
  @IsOptional()
  roleId?: number;
}
