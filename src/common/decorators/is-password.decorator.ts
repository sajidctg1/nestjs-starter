import { applyDecorators } from "@nestjs/common";
import {
  MaxLength,
  MinLength,
  registerDecorator,
  type ValidationArguments,
  type ValidationOptions,
  ValidatorConstraint,
  type ValidatorConstraintInterface,
} from "class-validator";

const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*\W).*$/;

@ValidatorConstraint({ async: true })
class IsPasswordConstraint implements ValidatorConstraintInterface {
  async validate(value: string, _arguments: ValidationArguments) {
    return PASSWORD_REGEX.test(value);
  }

  defaultMessage(arguments_: ValidationArguments) {
    const property = arguments_.property;

    return `${property} should contain at least one lowercase letter, one uppercase letter, one numeric digit, and one special character`;
  }
}

function IsPassword(validationOptions?: ValidationOptions): PropertyDecorator {
  return function (object: Record<string, any>, propertyName: string | symbol) {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName as string,
      options: validationOptions,
      constraints: [],
      validator: IsPasswordConstraint,
    });
  };
}

export function IsPasswordField(
  validationOptions?: ValidationOptions & {
    minLength?: number;
    maxLength?: number;
  }
) {
  return applyDecorators(
    MinLength(6),
    MaxLength(40),
    IsPassword(validationOptions)
  );
}
