import { expect, test } from "@playwright/test";

test("home page loads with Verdyx branding", async ({ page }) => {
  await page.goto("/");

  await expect(page).toHaveTitle(/Verdyx/i);
  await expect(page.getByText(/Verdyx/i).first()).toBeVisible();
});

test("login page renders the login form", async ({ page }) => {
  await page.goto("/login");

  await expect(page.getByRole("button", { name: "Sign in", exact: true })).toBeVisible();
});

test("register page renders the registration form", async ({ page }) => {
  await page.goto("/register");

  await expect(page.getByRole("button", { name: /register|create/i })).toBeVisible();
});

test("dashboard route is protected for anonymous users", async ({ page }) => {
  await page.goto("/dashboard");

  await expect(page).toHaveURL(/login|dashboard/);
});
