import secs from './secs.js'

export default (str: string): boolean => {
  try {
    const value = secs(str);
    return typeof value === 'number' && !isNaN(value);
  } catch (err) {
    return false;
  }
}
