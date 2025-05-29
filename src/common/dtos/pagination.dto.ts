import { IsBoolean, IsDateString, IsOptional, IsString } from "class-validator";

import { ToBoolean } from "../decorators/to-boolean.decorator";

export abstract class PaginationDto {
  /**
   * From date filter
   */
  @IsOptional()
  @IsDateString({ strict: true })
  fromDate?: Date;

  /**
   * From date filter
   */
  @IsOptional()
  @IsDateString({ strict: true })
  toDate?: Date;

  /**
   *  The search query
   */
  @IsOptional()
  @IsString({})
  search?: string;

  /**
   * The `withDeleted` property is a boolean flag that
   * indicates whether to include deleted items in the
   * results or not.
   */
  @IsOptional()
  @ToBoolean()
  @IsBoolean()
  withDeleted = false;

  /**
   * The `relations` property is used to specify which related
   * entities should be included in the query
   * results.
   */
  @IsOptional()
  @IsString({ each: true })
  relations: string[] = [];

  /**
   * The `fields` property is used to specify which
   * entities field should be included in the query
   * results.
   */
  @IsOptional()
  @IsString({ each: true })
  fields: string[] = [];
}
