import { Transform } from "class-transformer";
/**
 * It trims the value of a property and replaces multiple spaces with a single space
 * @returns A function that takes a parameter and returns a value.
 */
export function Trim() {
  return Transform((parameters) => {
    const value = parameters.value as string[] | string;

    if (value instanceof Array)
      return value.map((v: string) => v.trim().replaceAll(/\s\s+/g, " "));

    return value.trim().replaceAll(/\s\s+/g, " ");
  });
}

/**
 * It converts a string to a boolean
 * @returns A function that returns a PropertyDecorator
 */

export function ToBoolean() {
  return Transform(
    (parameters) => {
      switch (parameters.value) {
        case "true": {
          return true;
        }
        case "false": {
          return false;
        }
        default: {
          return parameters.value as boolean;
        }
      }
    },
    { toClassOnly: true }
  );
}

/**
 * It takes a string, sanitizes it, and returns the sanitized string
 * @returns A decorator function that will be applied to the class.
 */

export function Sanitize(): PropertyDecorator {
  return Transform(
    ({ value }: { value: unknown }) => {
      if (value instanceof Array) {
        return value.map((v) => {
          if (typeof v === "string") {
            // TODO: install package
            // return DOMPurify.sanitize(v);
          }

          return v;
        });
      }

      if (typeof value === "string") {
        // TODO: install package
        // return DOMPurify.sanitize(value);
      }

      return value;
    },
    { toClassOnly: true }
  );
}
