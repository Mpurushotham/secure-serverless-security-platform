import type { Config } from "jest";

/**
 * One project per test layer, following aws-samples/serverless-test-samples.
 *
 * The layering is what lets `npm test` run on a credential-free clone: unit and
 * invariants need nothing, while security-e2e needs a deployed stack. Selecting
 * by project rather than skipping at runtime means an un-runnable layer is
 * visibly *not selected*, instead of reporting as a pass.
 */
const config: Config = {
  projects: [
    {
      displayName: "unit",
      testEnvironment: "node",
      testMatch: ["<rootDir>/test/unit/**/*.test.ts"],
      transform: { "^.+\\.tsx?$": ["ts-jest", { tsconfig: "<rootDir>/tsconfig.json" }] },
    },
    {
      displayName: "invariants",
      testEnvironment: "node",
      testMatch: ["<rootDir>/test/invariants/**/*.test.ts"],
      transform: { "^.+\\.tsx?$": ["ts-jest", { tsconfig: "<rootDir>/tsconfig.json" }] },
    },
    {
      displayName: "security",
      testEnvironment: "node",
      testMatch: ["<rootDir>/test/security/**/*.test.ts"],
      transform: { "^.+\\.tsx?$": ["ts-jest", { tsconfig: "<rootDir>/tsconfig.json" }] },
    },
  ],
};

export default config;
