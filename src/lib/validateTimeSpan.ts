import secs from './secs.js'

export function validateTimeSpan(str: string) {
  const value = secs(str);
  const isValidNumber = typeof value === 'number' && !isNaN(value);
  if (!isValidNumber) {
    throw new TypeError('Number in time span string must be parseable as a float');
  }
}
