import { Type } from "class-transformer";
import {
  IsEnum,
  IsInt,
  IsNumber,
  IsOptional,
  IsPositive,
  IsString,
  Max,
  Min,
} from "class-validator";

import { PaginationDto } from "./pagination.dto";

export class OffsetPaginationDto extends PaginationDto {
  @IsOptional()
  @IsNumber()
  page = 1;

  @IsOptional()
  @Type(() => Number)
  @Min(1)
  @Max(1000)
  @IsInt()
  @IsPositive()
  limit = 10;

  @IsOptional()
  @IsString()
  orderBy = "id";

  @IsOptional()
  @IsEnum({ desc: "desc", asc: "asc" })
  order: "desc" | "asc" = "desc";
}
