# Concordion Usage Advice #

There was an issue related to the execute-assign statement in html files.

To produce this issue, you can add the following code in a html file:

```html
<p c:set="#myValue" c:execute="myMethodThatReturnsAvalue()" ></p>
<p c:echo="#myValue"></p>
```

The expected behavior is that the value returned by the method `myMethodThatReturnsAvalue()` 
is assigned to the variable `myValue` and then echoed in the second paragraph. However the right
syntax to use is:

```html
<p c:execute="#myValue = myMethodThatReturnsAvalue()" ></p>
<p c:echo="#myValue"></p>
```

Also, if the method returns a value you can use directly:

```html
<p c:echo="myMethodThatReturnsAvalue()" ></p>
```

This issue is happening related to the following statements:

```html
<p>And the token is <span concordion:assertEquals="true"
           concordion:execute="#isExpired = isTokenExpired(#expiredToken)">expired</span></p>
```

The right way to do it is:

```html
<p>And the token is <span
           concordion:assertTrue="#isExpired = isTokenExpired(#expiredToken)">expired</span></p>
```


Other statements that are not working are:

```html
        <p>Then the result is <span concordion:assertEquals="SUCCESS"
           concordion:execute="#result = testCustomClaims(#userId, #secretKey, #customClaim, #customValue)">#result</span></p>
```

The right way to do it is:

```html
        <p>Then the result is <span
        concordion:assertEquals="#result = testCustomClaims(#userId, #secretKey, #customClaim, #customValue)">SUCCESS</span></p>
```