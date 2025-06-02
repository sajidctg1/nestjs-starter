import { UnprocessableEntityException } from "@nestjs/common";

export class ValidationException extends UnprocessableEntityException {
  public fields: Array<{ field: any; error: string }>;

  constructor(field: string, error: string) {
    super({
      message: "Validation failed!",
      fields: [{ field, error: [error] }],
    });
  }
}
