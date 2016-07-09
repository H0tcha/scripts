#!/usr/bin/python

import sys,zlib
from operator import mod

c0=24011801817789450966462111100395433945349607360462473172504044159969314174280568468435551330772849484332868065150653488315320611034318582219410423539297444483489263262229272526432636473315312609897397560398849700525306836719169356459887498188288774977722690851244457886063778279208586426796185322151601639942983278861870086703699244045482959033102976377669845585368650656016198601796216772210259942297461309893145102711213040774894226335697379415230365156395127084863667408078361756427156601759353978084747540387020149654797772290399153070284755821623666008218079569083110382189852979060129667085831132632022103463749
c1=6334623001467088207115004149090248437567639843406063930348278009261839128529723057867392779144402843791179085641267638610554040704999564880363817225448000911092431848464275285723117148411639874088074867330755148734968472181191066037644782214516042447860647327731959655325252610210270727484138850425597129794988655902712111558361281448102573943847384314030134168332841366774414342959707157578598829227798333581811512312510888129513905963676725261593006158332939366309998946893955381678846680060587994890167942393026149589899718070763590507191265439197485988892965298855345883406592949187829635945687201252508615474387
c2=16760148561919014728546754236347000905468430224670329063680895443928178522407860095338161230104447911233423450277711795410013849539960934886186379443661795366508072353910531689949126575737578863374121487796843030719653537844782497978333725431432415915302155583469501549019938352315611728690912651504155773490630912889514512664427825306267707563749867608210547294080349006845433869265879870253579116498310883805790980560404713132958287020424754462186469386970978198245852882910492497527179790132652877765992999087207538716001519963215690550622261771843169125651521250688196260890382182338917196393020282320636987133378
n0=24088132627827854260227095241287626275732065067806834186623354160975432335738726761195386764521182300680771315112595887201110496947915341306995300639424916947195887557394756823646362931943509329576304869763822239754059209491009642827304173660157530461585166686801066985725892378374699903837941502096545364422456937171368348052512305352550642196383717659523753887771737636362716095040744434309074719750525888209779815280198441415524034624188190016783981969471718614753958068750629559832406702652702027110910387697750594631583852269075218123815223243656342016700606595192879304680108711721159527850434352951850296708923
n1=23483254155775775350914711489190204913200836124886389892537831743880612865434321302823443546235326623021942749852377298438662923115032903783705403434215933729346997746015514508309888420123476842789519251747448724493073678460705389773618508950296849197809182217608071220208495545565631056563132075962498678584365497520211315359228195682784983061715682353084850669467137345436861965174122706233056688371988516032076156384802287329260864873048825405302739597785532878330513867906014630466283952217150550536770857724915204592551622419582275637604509741570556093115598721039576035912695008696792321176970034181140058207777
n2=21685049991247660368182988485583486581457055242220602075778657795487471355128299636200853519281369590885861369405867190805781570843597256402017644522168291420451712315717125104835577811409412018897364870960396744957048861888374266275974873370851116023727499307881372861460087176458488674981386529588225210248009683705711143700140454529196318842914756578147590129446880038286919352470594193476130932296031708515329616909453996809704546249715524384990728834318712823570883295116225998406455955512785609689231119745517309645444775405860576042147951808039146904360247150670035530134895659926904787717762864845429595545919
modulus=[n0,n1,n2]
c=[c0,c1,c2]
e = 3
def eea(a,b):  
    v1 = [a,1,0]
    v2 = [b,0,1]
    while v2[0]<>0:
       p = v1[0]//v2[0] 
       v2, v1 = map(lambda x, y: x-y,v1,[p*vi for vi in v2]), v2
    return v1

def inverse(m,k):  
     v = eea(m,k)
     return (v[0]==1)*(v[1] % k)

def crt(ml,al):
     M  = reduce(lambda x, y: x*y,ml)
     Ms = [M/mi for mi in ml]   
     ys = [inverse(Mi, mi) for Mi,mi in zip(Ms,ml)] 
     return reduce(lambda x, y: x+y,[ai*Mi*yi for ai,Mi,yi in zip(al,Ms,ys)]) % M

def root(x,n):  
    high = 1
    while high ** n < x:
        high *= 2
    low = high/2
    while low < high:
        mid = (low + high) // 2
        if low < mid and mid**n < x:
            low = mid
        elif high > mid and mid**n > x:
            high = mid
        else:
            return mid
    return mid + 1

x=crt(modulus,c)
msg=root(x,e)
print hex(msg)[2:-1].decode('hex')
