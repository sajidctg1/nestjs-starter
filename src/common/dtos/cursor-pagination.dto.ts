import { Type } from "class-transformer";
import {
  IsBase64,
  IsEnum,
  IsInt,
  IsOptional,
  IsPositive,
  IsString,
  Min,
} from "class-validator";

import { PaginationDto } from "./pagination.dto";

// TODO: add filters

export class CursorPaginationDto extends PaginationDto {
  @IsOptional()
  @IsString()
  @IsBase64({})
  cursor?: string;

  @IsOptional()
  @Type(() => Number)
  @Min(1)
  @IsInt()
  @IsPositive()
  take = 10;

  @IsOptional()
  @IsEnum({ desc: "desc", asc: "asc" })
  order: "desc" | "asc" = "desc";
}
