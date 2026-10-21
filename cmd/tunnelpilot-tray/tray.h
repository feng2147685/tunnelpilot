#ifndef CF_TRAY_H
#define CF_TRAY_H

// 菜单项动作标识，与 Go 侧保持一致
#define CF_TRAY_TOGGLE 1
#define CF_TRAY_OPEN   2
#define CF_TRAY_QUIT   3

void tray_init(const char *title);
void tray_update(int running, int busy, const char *statusText, const char *toggleText);
void tray_run(void);
void tray_stop(void);

// 把三种状态的图标导出为 PNG，用于预览与校验
void tray_export_icons(const char *dir);

#endif
