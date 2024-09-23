
**说明**


    该文章是属于OverallAuth2\.0系列文章，每周更新一篇该系列文章（从0到1完成系统开发）。


    该系统文章，我会尽量说的非常详细，做到不管新手、老手都能看懂。


    说明：OverallAuth2\.0 是一个简单、易懂、功能强大的权限\+可视化流程管理系统。


结合上一篇文章使用，味道更佳：[从0到1搭建权限管理系统系列二 .net8 使用JWT鉴权（附当前源码）](https://github.com)


**有兴趣的朋友，请关注我吧(\*^▽^\*)。**


**![](https://img2024.cnblogs.com/blog/1158526/202408/1158526-20240824140446786-404771438.png)**


**关注我，学不会你来打我**


 **创建Token**


创建token的因素（条件）有很多，在该篇文章中，采用jwt配置和用户基本信息作为生成token的基本因素（读者可根据系统，自由改变生成token因素）。


在JwtPlugInUnit.CS中创建2个方法（JwtPlugInUnit.CS在上一篇文章中有写到）



```
方法一：PropValuesType方法
```



```
/// 
/// 反射获取字段
/// 
/// 
/// 
public static IEnumerable<(string Name, object Value, string Type)> PropValuesType(this object obj)
{
    List<(string a, object b, string c)> result = new List<(string a, object b, string c)>();

    var type = obj.GetType();
    var props = type.GetProperties();
    foreach (var item in props)
    {
        result.Add((item.Name, item.GetValue(obj), item.PropertyType.Name));
    }
    return result;
}
```



```
上述方法：PropValuesType是通过反射获取模型字段和属性。在本文章中，是为了提取登录人员信息，编写成List，组成生成token的因素之一。方法二：BuildToken方法
```



```
/// 
/// 生成Token
/// 
/// 登陆返回信息
/// 
public static LoginOutPut BuildToken(LoginInput loginResult)
{
    LoginOutPut result = new LoginOutPut();
    //获取配置
    var jwtsetting = AppSettingsPlugInUnit.GetNode("JwtSetting");

    //准备calims，记录登录信息
    var calims = loginResult.PropValuesType().Select(x => new Claim(x.Name, x.Value.ToString(), x.Type)).ToList();

    //创建header
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtsetting.SecurityKey));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    var header = new JwtHeader(creds);

    //创建payload
    var payload = new JwtPayload(jwtsetting.Issuer, jwtsetting.Audience, calims, DateTime.Now, DateTime.Now.AddMinutes(jwtsetting.ExpireSeconds));

    //创建令牌 
    var token = new JwtSecurityToken(header, payload);
    var tokenStr = new JwtSecurityTokenHandler().WriteToken(token);
    result.ExpiresDate = token.ValidTo.AddHours(8).ToString();
    result.Token = tokenStr;
    result.UserName = loginResult.UserName;

    return result;
}
```


    上述方法：BuildToken是创建token的核心代码，它通过用户信息\+jwt配置信息生成token，并返回token、用户名、token过期时间等信息（读者可以添加更多返回信息）。


    BuildToken中有2个模型，具体结构和位置如下：


![](https://img2024.cnblogs.com/blog/1158526/202409/1158526-20240923101858900-1006547626.png)


创建Model类，用于存放系统中模型。


LoginInput模型结构如下：




```
/// 
/// 登录输入模型
/// 
public class LoginInput
{
    /// 
    /// 用户名
    /// 
    public string? UserName { get; set; }

    /// 
    /// 密码
    /// 
    public string? Password { get; set; }

}
```


LoginOutPut模型结构如下：




```
   /// 
   /// 登录输入模型
   /// 
   public class LoginOutPut
   {
       /// 
       /// 用户名
       /// 
       public string? UserName { get; set; }

       /// 
       /// 密码
       /// 
       public string? Password { get; set; }

       /// 
       /// Token
       /// 
       public string? Token { get; set; }

       /// 
       /// Token过期时间
       /// 
       public string? ExpiresDate { get; set; }

   }
```


做完以上操作，用户就可以生成Token，但要把token运用到系统中，还需做以下操作。


**创建模块分组**


　　在ModeuleGroupEnum.cs中创建2个枚举，具体如下


　　说明：ModeuleGroupEnum.cs在[从0到1搭建权限管理系统系列一 .net8 使用Swagger（附当前源码）](https://github.com):[樱花宇宙官网](https://yzygzn.com) 文章中有说明（或者关注我的微信公众号）。




```
 /// 
 /// 模块分组
 /// 
 public enum ModeuleGroupEnum
 {
     /// 
     /// 系统菜单
     /// 
     SysMenu = 1,

     /// 
     /// 系统用户
     /// 
     SysUser = 2,

     /// 
     /// 基础
     /// 
     Base = 3,
 }
```


　　新增【系统用户】、【基础】2个枚举。


**创建新控制器**


**创建2个控制器：BaseController和SysUserController，结构如下**


**![](https://img2024.cnblogs.com/blog/1158526/202409/1158526-20240923103742248-2140429752.png)**


创建BaseController基础控制器，它存在的作用，就是承担系统中需要重写方法和获取用户基本信息的桥梁。


代码如下：




```
/// 
/// 系统基础模块
/// 
[ApiController]
[Route("api/[controller]/[action]")]
[ApiExplorerSettings(GroupName = nameof(ModeuleGroupEnum.Base))]
[Authorize]
public class BaseController : ControllerBase
{
    /// 
    /// 获取登陆人员信息
    /// 
    /// 
    [HttpGet]
    public LoginOutPut GetLoginUserMsg()
    {
        StringValues s = new StringValues();
        var auth = Request.Headers.TryGetValue("Authorization", out s);
        if (string.IsNullOrWhiteSpace(s))
            throw new Exception("登录信息失效");
        var token = new JwtSecurityTokenHandler().ReadJwtToken(s.ToString().Replace($"{JwtBearerDefaults.AuthenticationScheme} ", ""));
        LoginOutPut loginResult = new()
        {
            UserName = token.Claims.FirstOrDefault(f => f.Type == "UserName").Value,
            Password = Convert.ToString(token.Claims.FirstOrDefault(f => f.Type == "Password").Value),
        };
        return loginResult;

    }
}
```


解读下该方法：通过获取Headers中的Token，然后使用jwt反解析token获取在BuildToken方法中记录的用户基本信息。


说明：控制器上方存在\[Authorize]，只要有控制器继承基础控制【BaseController】，那么该控制器下的所有方法，都需要经过jwt验证。如果某一个接口不需要token验证，就在该接口上方添加 \[AllowAnonymous]


　　创建SysUserController控制器，并继承BaseController控制器，它的作用就是承担系统用户的所有接口，具体代码如下：




```
 /// 
 /// 用户模块
 /// 
 [ApiController]
 [Route("api/[controller]/[action]")]
 [ApiExplorerSettings(GroupName = nameof(ModeuleGroupEnum.SysUser))]
 public class SysUserController : BaseController
 {
     /// 
     /// 获取Token
     /// 
     /// 用户名
     /// 密码
     [HttpGet]
     [AllowAnonymous]
     public string GetToken(string userName, string password)
     {
         var loginResult = JwtPlugInUnit.BuildToken(new LoginInput { UserName = userName, Password = password });

         return loginResult.Token ?? string.Empty;
     }
 }
```


可以看到，该控制器下有2个接口，一个为获取token接口（可同时作为登录接口），一个为获取登录人员信息的接口（继承BaseController下的GetLoginUserMsg()方法）。


做完以上操作，jwt中token验证就完成啦，看一下成果。


不使用token访问接口，不会成功


![](https://img2024.cnblogs.com/blog/1158526/202409/1158526-20240923113057928-1452254262.png)


先获取token


![](https://img2024.cnblogs.com/blog/1158526/202409/1158526-20240923113120346-1651982446.png)


在添加使用token


![](https://img2024.cnblogs.com/blog/1158526/202409/1158526-20240923113140267-479757598.png)


点击Authorize确定使用


再次访问GetLoginUserMsg()接口，看下效果


![](https://img2024.cnblogs.com/blog/1158526/202409/1158526-20240923113348838-589372359.png)


**回复评论**


上一篇文章：[从0到1搭建权限管理系统系列二 .net8 使用JWT鉴权（附当前源码）](https://github.com)得到了较多评论，有指正的、有疑问的。


首先感谢大家的阅读，感谢大家的指正，也感谢大家的提问。


在这里我针对些问题，回复如下：


**回复一：**


![](https://img2024.cnblogs.com/blog/1158526/202409/1158526-20240923113907368-1363254433.png)


确实，在.net core 刚发布的时候，所有人在微软的引导下都对这一门的开源的框架，大家都叫它.net core ，它的出现也让c\#在生死的边缘，获得一线生机。但在.net core 3\.1（应该）之后，就改名叫.net5 .net8等。


**回复二：**


![](https://img2024.cnblogs.com/blog/1158526/202409/1158526-20240923114248608-1943758899.png)


jwt它是轻量级的库，所有它在这方面的处理，并不是很好。所以建议新增中间件验证过期token或者把Token存到数据库或缓存中，以此来操作复杂的鉴权验证。


**回复三：**


![](https://img2024.cnblogs.com/blog/1158526/202409/1158526-20240923114924139-1949957974.png)


艾特这2位朋友，你要的来了，顺便求关注博客园、关注微信公众号，不错过每次更新。


感谢你的耐心观看。


**如果对你有帮助，请关注我微信公众号吧(\*^▽^\*)。**


**源代码地址：https://gitee.com/yangguangchenjie/overall\-auth2\.0\-web\-api**


**帮我Star，谢谢。**


**有兴趣的朋友，请关注我微信公众号吧(\*^▽^\*)。**


**![](https://img2024.cnblogs.com/blog/1158526/202408/1158526-20240824140446786-404771438.png)**


关注我：一个全栈多端的宝藏博主，定时分享技术文章，不定时分享开源项目。关注我，带你认识不一样的程序世界



