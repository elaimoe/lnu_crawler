# LNU_crawler

适用于辽宁大学学生教务系统 [jwstudent.lnu.edu.cn](jwstudent.lnu.edu.cn)

功能：监控教务系统页面，当有成绩更新时发送邮件进行提醒。

填写scoreUpdateAlerts.py前面的配置部分即可使用：

```
# 配置
username = ''  # 学号
password = ''  # 密码
to_address = ''  # 收件人邮箱
mail_host = ''  # smtp服务器
mail_user = ''  # 发件人邮箱
mail_password = ''  # 邮箱smtp密钥
```

上完Python课一时兴起的产物，如需支持请提Issues。
涉及技术：验证码识别，登录持久化，解析成绩数据，smtp发送邮件。
可改进：引入系统日志，不在控制台输出。
