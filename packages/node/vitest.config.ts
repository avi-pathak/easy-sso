import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    include: ["tests/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "html", "lcov"],
      include: ["src/**/*.ts"],
      exclude: [
        "src/**/*.d.ts",
        "src/index.ts",
        "src/types/**",
        // Re-export barrels — no executable logic.
        "src/**/index.ts",
        // Interface/type-only modules — no runtime code to cover.
        "src/**/types.ts",
        "src/core/auth-provider.ts",
        "src/core/auth-user.ts",
        "src/core/claims.ts",
      ],
      thresholds: {
        statements: 95,
        branches: 90,
        functions: 95,
        lines: 95,
      },
    },
  },
});
