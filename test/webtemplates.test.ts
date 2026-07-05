import { describe, expect, it } from "vitest";
import { renderTemplate } from "../src/lib/web/templates";

describe("precompiled nunjucks rendering in workerd", () => {
  it("renders extends/blocks, custom filters, tests, and context functions", () => {
    const html = renderTemplate("spike/hello.html", {
      name: "d&w",
      user: { is_premium: () => true },
      items: ["a", null, "c"],
      created_at: "2026-07-05 10:00:00+00:00",
      url_for: (endpoint: string, params?: Record<string, unknown>) =>
        `/mock/${endpoint}?${new URLSearchParams(params as Record<string, string>)}`,
    });
    expect(html).toContain("<h1>Hello d&amp;w</h1>");
    expect(html).toContain('<span class="badge">Premium</span>');
    expect(html).toContain('<li data-i="0">a</li>');
    expect(html).toContain("(none)");
    expect(html).toContain('<li data-i="2">c</li>');
    expect(html).toContain("/mock/dashboard.index?page=2");
    expect(html).toContain("<div class=");
  });
});
