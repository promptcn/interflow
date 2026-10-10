/// 主题跟随系统:matchMedia 驱动 <html>.dark(theme.css 的挂类暗色策略)。
/// 桌面应用跟随系统是契约——不提供手动切换(与 color-scheme 语义一致,
/// UA 原生控件/滚动条由 theme.css 的 color-scheme 声明同步)。
export function initTheme(): void {
  const apply = (dark: boolean) => {
    document.documentElement.classList.toggle("dark", dark);
  };
  const query = window.matchMedia("(prefers-color-scheme: dark)");
  apply(query.matches);
  query.addEventListener("change", (e) => apply(e.matches));
}
