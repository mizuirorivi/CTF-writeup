def ex_euclid(x,y):
    c0,c1 = x,y
    a0,a1 = 1,0
    b0,b1 = 0,1

    while c1!=0:
        m = c0%c1
        q = c0//c1

        c0,c1 = c1,m
        a0,a1 = a1,(a0-q*a1)
        b0,b1 = b1,(b0-q*b1)
    return a0,b0
e1 = 11
e2 = 13
c1 = 80265690974140286785447882525076768851800986505783169077080797677035805215248640465159446426193422263912423067392651719120282968933314718780685629466284745121303594495759721471318134122366715904
c2 = 14451037575679461333658489727928902053807202350950440400755535465672646289383249206721118279217195146247129636809289035793102103248547070620691905918862697416910065303500798664102685376006097589955370023822867897020714767877873664
n = int(input())
a1,a2 = ex_euclid(7,9)
print(a1)
print(a2)
s1,s2 = ex_euclid(e1,e2)
v = (c1^s1) % n
w = (c2^s2) % n
x = (v*w) % n
print("\n\n\n\n")
print("x=")
print(x)
