const reporters = ["summary"];

if (!('CI' in process.env)) {
  reporters.push("progress");
}

const browsers = {
  safari_latest: {
    base: "BrowserStack",
    browser: "safari",
    os: "OS X",
    os_version: "Monterey",
  },
  safari_lowest: {
    base: "BrowserStack",
    browser: "safari",
    os: "OS X",
    os_version: "High Sierra",
  },
  ios_15: {
    base: "BrowserStack",
    device: "iPhone XS",
    os: "ios",
    real_mobile: true,
    os_version: "15",
  },
  ios_14: {
    base: "BrowserStack",
    device: "iPhone XS",
    os: "ios",
    real_mobile: true,
    os_version: "14",
  },
  ios_13: {
    base: "BrowserStack",
    device: "iPhone XS",
    os: "ios",
    real_mobile: true,
    os_version: "13",
  },
  ios_12: {
    base: "BrowserStack",
    device: "iPhone XS",
    os: "ios",
    real_mobile: true,
    os_version: "12",
  },
};

module.exports = function (config) {
  config.set({
    basePath: "",
    hostname: "127.0.0.1",
    frameworks: ["qunit"],
    plugins: [
      "karma-qunit",
      "karma-browserstack-launcher",
      "karma-summary-reporter",
    ],
    files: ["dist-browser-tests/*.js"],
    reporters,
    port: 9876,
    autoWatch: false,
    browserStack: {
      username: process.env.BROWSERSTACK_USERNAME,
      accessKey: process.env.BROWSERSTACK_ACCESS_KEY,
    },
    customLaunchers: browsers,
    logLevel: config.LOG_WARN,
    client: {
      qunit: {
        showUI: true,
        testTimeout: 5000,
        hidepassed: true
      },
    },
    browsers: Object.keys(browsers),
    singleRun: true,
    retryLimit: 0,
    summaryReporter: {
      show: 'all',
      overviewColumn: true,
      browserList: 'always'
    }
  });
};
