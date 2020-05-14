#------------------------------------------------------------------------
#Controller utilizado para calcular CVSS 3.1 para los factores de riesgo
#Se definen los catalogos en base a la documentación de CVSS 3.1
#------------------------------------------------------------------------
import base64
import math
from decimal import Decimal as D

#---------------------------------------------------------------------------
#Se definen las metricas base, temporal y ambiental
#Las metricas ese cargan automaticamente cuando se crea una nueva instancia
#---------------------------------------------------------------------------
@auth.requires_login()
def GrupoMetrica():
    #db.GrupoMetrica.id.readable = False
    db.GrupoMetrica.LogJefeRiesgo.writable = False
    db.GrupoMetrica.LogAnalistaRiesgo.writable = False
    db.GrupoMetrica.AprobacionJefeRiesgo.writable = False
    db.GrupoMetrica.AprobacionAnalistaRiesgo.writable = False
    db.GrupoMetrica.Nombre.writable = False
    Tabla = 'GrupoMetrica'
    fields = (db.GrupoMetrica.id, db.GrupoMetrica.Nombre, db.GrupoMetrica.Descripcion, db.GrupoMetrica.AprobacionJefeRiesgo)
    #----------------------------------------------------------
    #Se usa if para obtener los queries/parametros de busqueda
    #y despues de ejecutar el proceso el usuario visualice los
    #mismos registros
    #----------------------------------------------------------
    if request.vars.get('keywords'):
        links = [lambda row: A(T('Approve'),_class='button btn btn-success',_href=URL("cvss","RegistroLog", args=[row.id, Tabla, "1", base64.b64encode(request.vars.get('keywords'))] )), lambda row: A(T('Unlock'),_class='button btn btn-primary',_href=URL("cvss","RegistroLog", args=[row.id, Tabla, "0", base64.b64encode(request.vars.get('keywords'))]))]
    else:
        links = [lambda row: A(T('Approve'),_class='button btn btn-success',_href=URL("cvss","RegistroLog", args=[row.id, Tabla, "1"] )), lambda row: A(T('Unlock'),_class='button btn btn-primary',_href=URL("cvss","RegistroLog", args=[row.id, Tabla, "0"]))]
    if auth.has_membership(role='riskAnalyst') or auth.has_membership(role='riskManager') or auth.has_membership(role='admin'):
        #-------------------------------------------------------
        #Se llama a la funcion ActualizaAprobacion para que 
        #se solicite nuevamente autorizacion en caso de edicion
        #-------------------------------------------------------
        ActualizaAprobacion(Tabla)
        form = SQLFORM.grid(db.GrupoMetrica, links=links, fields=fields, searchable=True, create=False, editable=True, deletable=False, user_signature=True, paginate=10, maxtextlength=500)
    elif auth.has_membership(role='auditAnalyst') or auth.has_membership(role='auditManager') or auth.has_membership(role='guest'):
        form = SQLFORM.grid(db.GrupoMetrica, fields=fields, searchable=True, create=False, editable=False, deletable=False, user_signature=True, paginate=10, maxtextlength=500)
    else:
        redirect(URL('default','index'))
    return dict(form=form)

#------------------------------------------------------
#Catalogo para definir el detalle de las metricas CVSS
#------------------------------------------------------
@auth.requires_login()
def Metrica():
    #db.Metrica.id.readable = False
    db.Metrica.LogJefeRiesgo.writable = False
    db.Metrica.LogAnalistaRiesgo.writable = False
    db.Metrica.AprobacionJefeRiesgo.writable = False
    db.Metrica.AprobacionAnalistaRiesgo.writable = False
    db.Metrica.Nombre.writable = False
    db.Metrica.Codigo.writable = False
    db.Metrica.GrupoMetricaId.writable = False
    Tabla = 'Metrica'
    fields = (db.Metrica.id, db.Metrica.GrupoMetricaId, db.Metrica.Nombre, db.Metrica.Descripcion, db.Metrica.Codigo, db.Metrica.AprobacionJefeRiesgo)
    #----------------------------------------------------------
    #Se usa if para obtener los queries/parametros de busqueda
    #y despues de ejecutar el proceso el usuario visualice los
    #mismos registros
    #----------------------------------------------------------
    if request.vars.get('keywords'):
        links = [lambda row: A(T('Approve'),_class='button btn btn-success',_href=URL("cvss","RegistroLog", args=[row.id, Tabla, "1", base64.b64encode(request.vars.get('keywords'))] )), lambda row: A(T('Unlock'),_class='button btn btn-primary',_href=URL("cvss","RegistroLog", args=[row.id, Tabla, "0", base64.b64encode(request.vars.get('keywords'))]))]
    else:
        links = [lambda row: A(T('Approve'),_class='button btn btn-success',_href=URL("cvss","RegistroLog", args=[row.id, Tabla, "1"] )), lambda row: A(T('Unlock'),_class='button btn btn-primary',_href=URL("cvss","RegistroLog", args=[row.id, Tabla, "0"]))]
    if auth.has_membership(role='riksAnalyst') or auth.has_membership(role='riskManager') or auth.has_membership(role='admin'):
        #-------------------------------------------------------
        #Se llama a la funcion ActualizaAprobacion para que 
        #se solicite nuevamente autorizacion en caso de edicion
        #-------------------------------------------------------
        ActualizaAprobacion(Tabla)
        form = SQLFORM.grid(db.Metrica, links=links, fields=fields, searchable=True, create=False, editable=True, deletable=False, user_signature=True, paginate=10, maxtextlength=500)
    elif auth.has_membership(role='auditAnalyst') or auth.has_membership(role='auditManager') or auth.has_membership(role='guest'):
        form = SQLFORM.grid(db.Metrica, fields=fields, searchable=True, create=False, editable=False, deletable=False, user_signature=True, paginate=10, maxtextlength=500)
    else:
        redirect(URL('default','index'))
    return dict(form=form)

#------------------------------------------------------------------
#Catalogo para asignar valores numericos de las metricas definidas
#------------------------------------------------------------------
@auth.requires_login()
def ValorMetrica():
    #db.ValorMetrica.id.readable = False
    db.ValorMetrica.LogJefeRiesgo.writable = False
    db.ValorMetrica.LogAnalistaRiesgo.writable = False
    db.ValorMetrica.AprobacionJefeRiesgo.writable = False
    db.ValorMetrica.AprobacionAnalistaRiesgo.writable = False
    db.ValorMetrica.MetricaId.writable = False
    db.ValorMetrica.Nombre.writable = False
    db.ValorMetrica.ValorMetrica.writable = False
    db.ValorMetrica.ValorNumerico.writable = False
    Tabla = 'ValorMetrica'
    fields = (db.ValorMetrica.id, db.ValorMetrica.MetricaId, db.ValorMetrica.Nombre, db.ValorMetrica.Descripcion, db.ValorMetrica.ValorMetrica, db.ValorMetrica.ValorNumerico, db.ValorMetrica.AprobacionJefeRiesgo)
    #----------------------------------------------------------
    #Se usa if para obtener los queries/parametros de busqueda
    #y despues de ejecutar el proceso el usuario visualice los
    #mismos registros
    #----------------------------------------------------------
    if request.vars.get('keywords'):
        links = [lambda row: A(T('Approve'),_class='button btn btn-success',_href=URL("cvss","RegistroLog", args=[row.id, Tabla, "1", base64.b64encode(request.vars.get('keywords'))] )), lambda row: A(T('Unlock'),_class='button btn btn-primary',_href=URL("cvss","RegistroLog", args=[row.id, Tabla, "0", base64.b64encode(request.vars.get('keywords'))]))]
    else:
        links = [lambda row: A(T('Approve'),_class='button btn btn-success',_href=URL("cvss","RegistroLog", args=[row.id, Tabla, "1"] )), lambda row: A(T('Unlock'),_class='button btn btn-primary',_href=URL("cvss","RegistroLog", args=[row.id, Tabla, "0"]))]
    if auth.has_membership(role='riskAnalyst') or auth.has_membership(role='riskManager') or auth.has_membership(role='admin'):
        #-------------------------------------------------------
        #Se llama a la funcion ActualizaAprobacion para que 
        #se solicite nuevamente autorizacion en caso de edicion
        #-------------------------------------------------------
        ActualizaAprobacion(Tabla)
        form = SQLFORM.grid(db.ValorMetrica, links=links, fields=fields, searchable=True, create=False, editable=True, deletable=False, user_signature=True, paginate=10, maxtextlength=500)
    elif auth.has_membership(role='auditAnalyst') or auth.has_membership(role='auditManager') or auth.has_membership(role='guest'):
        form = SQLFORM.grid(db.ValorMetrica, searchable=True, fields=fields, create=False, editable=False, deletable=False, user_signature=True, paginate=10, maxtextlength=500)
    else:
        redirect(URL('default','index'))
    return dict(form=form)

#-----------------------------------------------------------------
#Se evaluan los factores de riesgo de acuerdo a las metricas CVSS
#-----------------------------------------------------------------
@auth.requires_login()
def ValorMetricaSeguridadTi():
    db.ValorMetricaSeguridadTi.LogAnalistaRiesgo.writable = False
    db.ValorMetricaSeguridadTi.LogJefeRiesgo.writable = False
    db.ValorMetricaSeguridadTi.LogResponsableControl.writable = False
    db.ValorMetricaSeguridadTi.AprobacionAnalistaRiesgo.writable = False
    db.ValorMetricaSeguridadTi.AprobacionJefeRiesgo.writable = False
    db.ValorMetricaSeguridadTi.AprobacionResponsableControl.writable = False
    Tabla = 'ValorMetricaSeguridadTi'
    fields = (db.ValorMetricaSeguridadTi.id, db.ValorMetricaSeguridadTi.TratamientoRiesgoId, db.ValorMetricaSeguridadTi.ValorMetricaId, db.ValorMetricaSeguridadTi.Descripcion, db.ValorMetricaSeguridadTi.AprobacionJefeRiesgo)
    #----------------------------------------------------------
    #Se usa if para obtener los queries/parametros de busqueda
    #y despues de ejecutar el proceso el usuario visualice los
    #mismos registros
    #----------------------------------------------------------
    if request.vars.get('keywords'):
        links = [lambda row: A(T('Approve'),_class='button btn btn-success',_href=URL("cvss","RegistroLog", args=[row.id, Tabla, "1", base64.b64encode(request.vars.get('keywords'))] )), lambda row: A(T('Unlock'),_class='button btn btn-primary',_href=URL("cvss","RegistroLog", args=[row.id, Tabla, "0", base64.b64encode(request.vars.get('keywords'))]))]
    else:
        links = [lambda row: A(T('Approve'),_class='button btn btn-success',_href=URL("cvss","RegistroLog", args=[row.id, Tabla, "1"] )), lambda row: A(T('Unlock'),_class='button btn btn-primary',_href=URL("cvss","RegistroLog", args=[row.id, Tabla, "0"]))]
    if auth.has_membership(role='riskAnalyst') or auth.has_membership(role='riskManager') or auth.has_membership(role='admin'):
        #-------------------------------------------------------
        #Se llama a la funcion ActualizaAprobacion para que 
        #se solicite nuevamente autorizacion en caso de edicion
        #-------------------------------------------------------
        ActualizaAprobacion(Tabla)
        form = SQLFORM.grid(db.ValorMetricaSeguridadTi, fields=fields, links=links, searchable=True, create=True, editable=True, deletable=True, user_signature=True, paginate=10, maxtextlength=500)
    elif auth.has_membership(role='auditAnalyst') or auth.has_membership(role='auditManager') or auth.has_membership(role='guest'):
        form = SQLFORM.grid(db.ValorMetrizaSeguridadTi, fields=fields, searchable=True, create=False, editable=False, deletable=False, user_signature=True, paginate=10, maxtextlength=500)
    else:
        redirect(URL('default','index'))
    return dict(form=form)

#------------------------------------------------------------------------------------
#Esta funcion se utiliza para medir el impacto en base al sistema o activo de TI 
#Actualiza todos los registros de ValorMetricaSeguridadTi en base al sistema evaluado
#------------------------------------------------------------------------------------
@auth.requires_login()
@auth.requires( auth.has_membership(role='riskAnalyst') or auth.has_membership(role='riskManager') or auth.has_membership(role='admin') )
def CvssImpacto():
    TratamientoRiesgoId = db(db.TratamientoRiesgo.ActivoTiId==request.args(0)).select(db.TratamientoRiesgo.id)
    for i in TratamientoRiesgoId:
        db.ValorMetricaSeguridadTi.update_or_insert(( (db.ValorMetricaSeguridadTi.TratamientoRiesgoId==i) & ((db.ValorMetricaSeguridadTi.ValorMetricaId==14 ) | (db.ValorMetricaSeguridadTi.ValorMetricaId==15 ) | (db.ValorMetricaSeguridadTi.ValorMetricaId==16 ))), TratamientoRiesgoId=i, ValorMetricaId=request.args(1), Descripcion=base64.b64decode(request.args(4)) )
    for i in TratamientoRiesgoId:
        db.ValorMetricaSeguridadTi.update_or_insert(( (db.ValorMetricaSeguridadTi.TratamientoRiesgoId==i) & ((db.ValorMetricaSeguridadTi.ValorMetricaId==17 ) | (db.ValorMetricaSeguridadTi.ValorMetricaId==18 ) | (db.ValorMetricaSeguridadTi.ValorMetricaId==19 ))), TratamientoRiesgoId=i, ValorMetricaId=request.args(2), Descripcion=base64.b64decode(request.args(4)) )
    for i in TratamientoRiesgoId:
        db.ValorMetricaSeguridadTi.update_or_insert(( (db.ValorMetricaSeguridadTi.TratamientoRiesgoId==i) & ((db.ValorMetricaSeguridadTi.ValorMetricaId==20 ) | (db.ValorMetricaSeguridadTi.ValorMetricaId==21 ) | (db.ValorMetricaSeguridadTi.ValorMetricaId==22 ))), TratamientoRiesgoId=i, ValorMetricaId=request.args(3), Descripcion=base64.b64decode(request.args(4)) )
    redirect(URL('default','ActivoTi'))

#--------------------------------------------------------
#Son las formulas CVSS 3.1 de acuerdo a la documentacion
#--------------------------------------------------------
@auth.requires_login()
@auth.requires( auth.has_membership(role='riskAnalyst') or auth.has_membership(role='riskManager') or auth.has_membership(role='admin') )
def CvssEvaluation():
    if request.args(3):
        parametros = base64.b64decode(request.args(3))
    else:
        pass
    #----------------------------------------------------------------------------------------------
    #Se definen los valores minimos, en caso que no se evalue en el modulo ValorMetricaSeguridadTi
    #Por lo que si se evalua con estos valores, el resultado es 0, solo se evaluan metricas Base
    #----------------------------------------------------------------------------------------------

    #------------------------
    #Variables Iniciales Base
    #------------------------
    cvssBaseAV=0.2 #Physical
    cvssBaseAVString="P"
    cvssBaseAC=0.44 #High
    cvssBaseACString="H"
    cvssBasePR=0.27 #High
    cvssBasePRString="H"
    cvssBaseUI=0.62 #Required
    cvssBaseUIString="R"
    cvssBaseS =6.42 #Unhanged
    cvssBaseSString="U"
    cvssBaseC =0 #None
    cvssBaseCString="N"
    cvssBaseI =0 #None
    cvssBaseIString="N"
    cvssBaseA =0 #None
    cvssBaseAString="N"
    changed=0
    #------------------------------
    #Variables Iniciales Temporales
    #------------------------------
    cvssTempE  = 1 #Not Defined
    cvssTempEString  = "X"
    cvssTempRL = 1 #Not Defined
    cvssTempRLString = "X"
    cvssTempRC = 1 #Not Defined
    cvssTempRCString = "X"
    #--------------------------------
    #Variables Iniciales Ambientales
    #--------------------------------
    cvssEnvCR  = 1 #Not Defined
    cvssEnvCRString  = "X"
    cvssEnvIR  = 1 #Not Defined
    cvssEnvIRString  = "X"
    cvssEnvAR  = 1 #Not Defined
    cvssEnvARString  = "X"
    cvssEnvMAV = 1 #Physical
    cvssEnvMAVString = "P"
    cvssEnvMAC = 1 #High
    cvssEnvMACString = "H"
    cvssEnvMPR = 1 #High
    cvssEnvMPRString = "H"
    cvssEnvMUI = 1 #Required
    cvssEnvMUIString = "R"
    cvssEnvMS  = 1 #Unchanged
    cvssEnvMSString = "U"
    cvssEnvMC  = 0 #None
    cvssEnvMCString  = "N"
    cvssEnvMI  = 0 #None
    cvssEnvMIString  = "N"
    cvssEnvMA  = 0 #None
    cvssEnvMAString  = "N"
    changedE=0
    #---------------------------------------------
    #request.args(0) es el ID del factor de riesgo
    #---------------------------------------------
    cvss = db(db.ValorMetricaSeguridadTi.TratamientoRiesgoId==request.args(0)).select(db.ValorMetricaSeguridadTi.ALL)
    for s in cvss:
        #-----------------------------------------------------------------------
        #El grupo metrica 5 corresponde a "Base Metric Group | S | Scope (S)"
        #Los valores que se pueden tomar son 12 Changed(C), 13 Unchanged(U)
        #-----------------------------------------------------------------------
        if s.ValorMetricaId.MetricaId == 5:
            #--------------
            #12 Changed (C)
            #--------------
            if s.ValorMetricaId == 12:
                changed = 1
            #----------------
            #13 Unchanged (U)
            #----------------
            elif s.ValorMetricaId == 13:
                changed = 0
        #------------------------------------------------------------------------------------------
        #El grupo metrica 19 corresponde a "Environmental Metric Group | MS | Modified Scope (MS)"
        #Los valores son 64 Not Defined (X), 65 Modified Changed (C), 66 Modified Unchanged (U)	
        #------------------------------------------------------------------------------------------
        if s.ValorMetricaId.MetricaId == 19:
            #--------------
            #65 Changed (C)
            #--------------
            if s.ValorMetricaId == 65:
                changedE = 1
            #----------------
            #66 Unchanged (U)
            #----------------
            elif s.ValorMetricaId == 66:
                changedE = 0
        #for i in cvss:
        #------------------------------------------------
        #1 | Base Metric Group | AV | Attack Vector (AV)
        #------------------------------------------------
        if s.ValorMetricaId.MetricaId == 1:
            cvssBaseAV = s.ValorMetricaId.ValorNumerico
            cvssBaseAVString = s.ValorMetricaId.ValorMetrica
        #---------------------------------------------------
        #2 | Base Metric Group | AC | Attack Complexity (AC)
        #---------------------------------------------------
        if s.ValorMetricaId.MetricaId == 2:
            cvssBaseAC = s.ValorMetricaId.ValorNumerico
            cvssBaseACString = s.ValorMetricaId.ValorMetrica
        #-----------------------------------------------------
        #3 | Base Metric Group | PR | Privileges Required (PR)
        #-----------------------------------------------------
        if s.ValorMetricaId.MetricaId == 3 and changed == 0:
            cvssBasePR = s.ValorMetricaId.ValorNumerico
            cvssBasePRString = s.ValorMetricaId.ValorMetrica
        elif s.ValorMetricaId.MetricaId==3 and changed==1 and s.ValorMetricaId==7: #Changed (C) & PR High (H)
            cvssBasePR=0.5
            cvssBasePRString = s.ValorMetricaId.ValorMetrica
        elif s.ValorMetricaId.MetricaId==3 and changed==1 and s.ValorMetricaId==8: #Changed (C) & PR Low (L)
            cvssBasePR=0.68
            cvssBasePRString = s.ValorMetricaId.ValorMetrica
        #--------------------------------------------------
        #4 | Base Metric Group | UI | User Interaction (UI)
        #--------------------------------------------------
        if s.ValorMetricaId.MetricaId == 4:
            cvssBaseUI = s.ValorMetricaId.ValorNumerico
            cvssBaseUIString = s.ValorMetricaId.ValorMetrica
        #--------------------------------------
        #5 | Base Metric Group | S | Scope (S)
        #--------------------------------------
        if s.ValorMetricaId.MetricaId == 5:
            cvssBaseS = s.ValorMetricaId.ValorNumerico
            cvssBaseSString = s.ValorMetricaId.ValorMetrica
        #-------------------------------------------
        #6 | Base Metric Group | C | Confidentiality
        #-------------------------------------------
        if s.ValorMetricaId.MetricaId == 6:
            cvssBaseC = s.ValorMetricaId.ValorNumerico
            cvssBaseCString = s.ValorMetricaId.ValorMetrica
        #-----------------------------------------
        #7 | Base Metric Group | I | Integrity (I)
        #-----------------------------------------
        if s.ValorMetricaId.MetricaId == 7:
            cvssBaseI = s.ValorMetricaId.ValorNumerico
            cvssBaseIString = s.ValorMetricaId.ValorMetrica
        #--------------------------------------------
        #8 | Base Metric Group | A | Availability (A)
        #--------------------------------------------
        if s.ValorMetricaId.MetricaId == 8:
            cvssBaseA = s.ValorMetricaId.ValorNumerico
            cvssBaseAString = s.ValorMetricaId.ValorMetrica
        #--------------------
        #Metricas temporales
        #--------------------
        if s.ValorMetricaId.MetricaId == 9:
            cvssTempE = s.ValorMetricaId.ValorNumerico
            cvssTempEString = s.ValorMetricaId.ValorMetrica
        if s.ValorMetricaId.MetricaId == 10:
            cvssTempRL = s.ValorMetricaId.ValorNumerico
            cvssTempRLString = s.ValorMetricaId.ValorMetrica
        if s.ValorMetricaId.MetricaId == 11:
            cvssTempRC = s.ValorMetricaId.ValorNumerico
            cvssTempRCString = s.ValorMetricaId.ValorMetrica
        #---------------------
        #Metricas ambientales
        #---------------------
        if s.ValorMetricaId.MetricaId == 12:
            cvssEnvCR = s.ValorMetricaId.ValorNumerico
            cvssEnvCRString = s.ValorMetricaId.ValorMetrica
        if s.ValorMetricaId.MetricaId == 13:
            cvssEnvIR = s.ValorMetricaId.ValorNumerico
            cvssEnvIRString = s.ValorMetricaId.ValorMetrica
        if s.ValorMetricaId.MetricaId == 14:
            cvssEnvAR = s.ValorMetricaId.ValorNumerico
            cvssEnvARString = s.ValorMetricaId.ValorMetrica
        if s.ValorMetricaId.MetricaId == 15:
            cvssEnvMAV = s.ValorMetricaId.ValorNumerico
            cvssEnvMAVString = s.ValorMetricaId.ValorMetrica
        if s.ValorMetricaId.MetricaId == 16:
            cvssEnvMAC = s.ValorMetricaId.ValorNumerico
            cvssEnvMACString = s.ValorMetricaId.ValorMetrica
        #---------------------
        #Si no cambio el scope
        #---------------------
        if s.ValorMetricaId.MetricaId == 17 and changedE == 0:
            cvssEnvMPR = s.ValorMetricaId.ValorNumerico
            cvssEnvMPRString = s.ValorMetricaId.ValorMetrica
        #----------------------------------------------
        #Si cambio se asigna de acuerdo a su criticidad
        #----------------------------------------------
        elif s.ValorMetricaId.MetricaId == 17 and changedE == 1 and s.ValorMetricaId == 58: #Changed (C) & PR High (H)
            cvssEnvMPR=0.5
            cvssEnvMPRString = s.ValorMetricaId.ValorMetrica
        elif s.ValorMetricaId.MetricaId == 17 and changedE == 1 and s.ValorMetricaId == 59: #Changed (C) & PR Low (L)
            cvssEnvMPR=0.68
            cvssEnvMPRString = s.ValorMetricaId.ValorMetrica
        #-------------------------------
        #Modified User Interaction (MUI)
        #-------------------------------
        if s.ValorMetricaId.MetricaId == 18:
            cvssEnvMUI = s.ValorMetricaId.ValorNumerico
            cvssEnvMUIString = s.ValorMetricaId.ValorMetrica
        #-------------------
        #Modified Scope (MS)
        #-------------------
        if s.ValorMetricaId.MetricaId == 19:
            cvssEnvMS = s.ValorMetricaId.ValorNumerico
            cvssEnvMSString = s.ValorMetricaId.ValorMetrica
        #-------------------------------
        #Modified Confidentiality (MC)
        #-------------------------------
        if s.ValorMetricaId.MetricaId == 20:
            cvssEnvMC = s.ValorMetricaId.ValorNumerico
            cvssEnvMCString = s.ValorMetricaId.ValorMetrica
        #-----------------------
        #Modified Integrity (MI)
        #-----------------------
        if s.ValorMetricaId.MetricaId == 21:
            cvssEnvMI = s.ValorMetricaId.ValorNumerico
            cvssEnvMIString = s.ValorMetricaId.ValorMetrica
        #---------------------------
        #Modified Availability (MA)
        #---------------------------
        if s.ValorMetricaId.MetricaId == 22:
            cvssEnvMA = s.ValorMetricaId.ValorNumerico
            cvssEnvMAString = s.ValorMetricaId.ValorMetrica

    #---------------------
    #Calculo metrica BASE
    #---------------------
    ISS = 1-( (1-cvssBaseC) * (1-cvssBaseI) * (1-cvssBaseA) )
    Impact = ( ((7.52) * (ISS - 0.029)) - ( (3.25) * (math.pow((ISS - 0.02), 15))) )
    for i in cvss:
        if i.ValorMetricaId==13: #Unchanged (U)
            Impact = (6.42) * (ISS)
        elif i.ValorMetricaId==12:
            Impact = ( ((7.52) * (ISS - 0.029)) - ( (3.25) * (math.pow((ISS - 0.02), 15))) )
    Exploitability = (8.22) * (cvssBaseAV) * (cvssBaseAC) * (cvssBasePR) * (cvssBaseUI)
    BaseScore = roundup( min( 1.08*(Impact + Exploitability)  , 10) )
    if Impact <=0:
        BaseScore=0
    for i in cvss:
        if i.ValorMetricaId==13: #Unchanged (U)
            BaseScore = roundup( min( Impact + Exploitability  , 10) )
        elif i.ValorMetricaId==12:
            BaseScore = roundup( min( (1.08) * (Impact + Exploitability)  , 10) )
    #-----------------------------------------------------
    #Calculo metrica TEMPORAL (En proceso de desarrollo)
    #-----------------------------------------------------
    if BaseScore<=0:
        TempScore = 0
    else:
        TempScore = roundup(BaseScore * D(cvssTempE) * D(cvssTempRL) * D(cvssTempRC) )
    #----------------------------------------------------
    #Calculo metrica AMBIENTAL (En proceso de desarrollo)
    #----------------------------------------------------
    ISCM = min(1-((1-cvssEnvCR * cvssEnvMC) * (1-cvssEnvIR * cvssEnvMI) * (1-cvssEnvAR * cvssEnvMA)), 0.915 ) 
    ImpactM = 0
    if changedE==1:
        ImpactM = ( (7.52) * (ISCM - 0.029) -  3.25 * (math.pow( ISCM * 0.9731 - 0.02, 13)) )
    elif changedE==0:
        ImpactM = (6.42) * (ISCM)

    ExploitabilityM = (8.22) * (cvssEnvMAV) * (cvssEnvMAC) * (cvssEnvMPR) * (cvssEnvMUI)
    BaseScoreM = roundup(roundup( min( 1.08*(ImpactM + ExploitabilityM)  , 10) ) * D(cvssTempE) * D(cvssTempRL) * D(cvssTempRC))
    if ImpactM <= 0:
        BaseScoreM = 0
    for i in cvss:
        if i.ValorMetricaId==66: #Unchanged (U)
            BaseScoreM = roundup(roundup( min( ImpactM + ExploitabilityM  , 10) ) * D(cvssTempE) * D(cvssTempRL) * D(cvssTempRC))
        elif i.ValorMetricaId==65:
            BaseScoreM = roundup(roundup( min( 1.08*(ImpactM + ExploitabilityM)  , 10) ) * D(cvssTempE) * D(cvssTempRL) * D(cvssTempRC))
    #-----------------------
    #Definicion de vectores
    #-----------------------
    VectorString = "CVSS:3.1/AV:"+str(cvssBaseAVString)+"/AC:"+str(cvssBaseACString)+"/PR:"+str(cvssBasePRString)+"/UI:"+str(cvssBaseUIString)+"/S:"+str(cvssBaseSString)+"/C:"+str(cvssBaseCString)+"/I:"+str(cvssBaseIString)+"/A:"+str(cvssBaseAString)
    VectorStringE = "CVSS:3.1/AV:"+str(cvssBaseAVString)+"/AC:"+str(cvssBaseACString)+"/PR:"+str(cvssBasePRString)+"/UI:"+str(cvssBaseUIString)+"/S:"+str(cvssBaseSString)+"/C:"+str(cvssBaseCString)+"/I:"+str(cvssBaseIString)+"/A:"+str(cvssBaseAString)+"/E:"+str(cvssTempEString)+"/RL:"+str(cvssTempRLString)+"/RC:"+str(cvssTempRCString)+"/CR:"+str(cvssEnvCRString)+"/IR:"+str(cvssEnvIRString)+"/AR:"+str(cvssEnvARString)+"/MAV:"+str(cvssEnvMAVString)+"/MAC:"+str(cvssEnvMACString)+"/MPR:"+str(cvssEnvMPRString)+"/MUI:"+str(cvssEnvMUIString)+"/MS:"+str(cvssEnvMSString)+"/MC:"+str(cvssEnvMCString)+"/MI:"+str(cvssEnvMIString)+"/MA:"+str(cvssEnvMAString)

    #--------------------------------------------
    #Condicion para solo considerar metricas base
    #--------------------------------------------
    if request.vars.metrica =='base':
        db.TratamientoRiesgo.update_or_insert(db.TratamientoRiesgo.id == request.args(0), CuantificacionCVSS = BaseScore, VectorCVSS = VectorString)
        if request.args(3):
            redirect(URL('default', 'TratamientoRiesgo', vars=dict(keywords = parametros)))
        else:
            redirect(URL('default', 'TratamientoRiesgo'))
    #--------------------------------------------------
    #Condicion para solo considerar metricas temporales
    #--------------------------------------------------
    elif request.vars.metrica == 'temp':
        db.TratamientoRiesgo.update_or_insert(db.TratamientoRiesgo.id == request.args(0) , CuantificacionCVSS = BaseScore, VectorCVSS = VectorString, CuantificacionCVSSE = BaseScoreM, VectorCVSSE = VectorStringE)
        if request.args(3):
            redirect(URL('default', 'EvaluacionControl', vars=dict(keywords = parametros)))
        else:
            redirect(URL('default', 'EvaluacionControl'))
    else:
        pass

def roundup(num):
    return D(math.ceil(num * 10) / 10).quantize(D("0.1"))

#------------------------------------------------------
#Funcion para indicar que un registro ha sido editado
#y que requiere nuevamente de aprobacion
#------------------------------------------------------
@auth.requires_login()
@auth.requires(auth.has_membership(role='riskManager') or auth.has_membership(role='auditManager') or auth.has_membership(role='riskAnalyst') or auth.has_membership(role='auditAnalyst') or auth.has_membership(role='processOwner') or auth.has_membership(role='controlResp') or auth.has_membership(role='admin') or auth.has_membership(role='guest'))
def ActualizaAprobacion(Tabla):
    if 'edit' in request.args:
        if Tabla == 'GrupoMetrica':
            db(db.GrupoMetrica.id == request.args[len(request.args)-1]).update(AprobacionJefeRiesgo='F')
            db(db.GrupoMetrica.id == request.args[len(request.args)-1]).update(AprobacionAnalistaRiesgo='F')
        if Tabla == 'Metrica':
            db(db.Metrica.id == request.args[len(request.args)-1]).update(AprobacionJefeRiesgo='F')
            db(db.Metrica.id == request.args[len(request.args)-1]).update(AprobacionAnalistaRiesgo='F')
        if Tabla == 'ValorMetrica':
            db(db.ValorMetrica.id == request.args[len(request.args)-1]).update(AprobacionJefeRiesgo='F')
            db(db.ValorMetrica.id == request.args[len(request.args)-1]).update(AprobacionAnalistaRiesgo='F')
        if Tabla == 'ValorMetricaSeguridadTi':
            db(db.ValorMetricaSeguridadTi.id == request.args[len(request.args)-1]).update(AprobacionJefeRiesgo='F')
            db(db.ValorMetricaSeguridadTi.id == request.args[len(request.args)-1]).update(AprobacionAnalistaRiesgo='F')

#----------------------------------------------------------------------------
#Funcion para generar registros de autorizaciones y modificacion de registros
#----------------------------------------------------------------------------
@auth.requires_login()
def RegistroLog():
    signature = auth.user.username + ',' + request.client + ',' + str(request.now) + ',' + str(response.session_id)
    if request.args(3):
        parametros = base64.b64decode(request.args(3))
    else:
        pass
    if request.args(1) == 'GrupoMetrica':
        if (auth.has_membership(role='riskManager') or auth.has_membership(role='admin')):
            if request.args(2)=='1':
                db(db.GrupoMetrica.id==request.args(0)).update(LogJefeRiesgo=signature)
                db(db.GrupoMetrica.id==request.args(0)).update(AprobacionJefeRiesgo='T')
            elif request.args(2)=='0':
                db(db.GrupoMetrica.id==request.args(0)).update(LogJefeRiesgo=signature)
                db(db.GrupoMetrica.id==request.args(0)).update(AprobacionJefeRiesgo='F')
        elif (auth.has_membership(role='riskAnalyst')):
            if request.args(2)=='1':
                db(db.GrupoMetrica.id==request.args(0)).update(LogAnalistaRiesgo=signature)
                db(db.GrupoMetrica.id==request.args(0)).update(AprobacionAnalistaRiesgo='T')
            elif request.args(2)=='0':
                db(db.GrupoMetrica.id==request.args(0)).update(LogAnalistaRiesgo=signature)
                db(db.GrupoMetrica.id==request.args(0)).update(AprobacionAnalistaRiesgo='F')
        if request.args(3):
            redirect(URL('cvss', 'GrupoMetrica', vars=dict(keywords=parametros)))
        else:
            redirect(URL('cvss', 'GrupoMetrica'))
    if request.args(1) == 'Metrica':
        if (auth.has_membership(role='riskManager') or auth.has_membership(role='admin')):
            if request.args(2)=='1':
                db(db.Metrica.id==request.args(0)).update(LogJefeRiesgo=signature)
                db(db.Metrica.id==request.args(0)).update(AprobacionJefeRiesgo='T')
            elif request.args(2)=='0':
                db(db.Metrica.id==request.args(0)).update(LogJefeRiesgo=signature)
                db(db.Metrica.id==request.args(0)).update(AprobacionJefeRiesgo='F')
        elif (auth.has_membership(role='riskAnalyst')):
            if request.args(2)=='1':
                db(db.Metrica.id==request.args(0)).update(LogAnalistaRiesgo=signature)
                db(db.Metrica.id==request.args(0)).update(AprobacionAnalistaRiesgo='T')
            elif request.args(2)=='0':
                db(db.Metrica.id==request.args(0)).update(LogAnalistaRiesgo=signature)
                db(db.Metrica.id==request.args(0)).update(AprobacionAnalistaRiesgo='F')
        if request.args(3):
            redirect(URL('cvss', 'Metrica', vars=dict(keywords=parametros)))
        else:
            redirect(URL('cvss', 'Metrica'))
    if request.args(1) == 'ValorMetrica':
        if (auth.has_membership(role='riskManager') or auth.has_membership(role='admin')):
            if request.args(2)=='1':
                db(db.ValorMetrica.id==request.args(0)).update(LogJefeRiesgo=signature)
                db(db.ValorMetrica.id==request.args(0)).update(AprobacionJefeRiesgo='T')
            elif request.args(2)=='0':
                db(db.ValorMetrica.id==request.args(0)).update(LogJefeRiesgo=signature)
                db(db.ValorMetrica.id==request.args(0)).update(AprobacionJefeRiesgo='F')
        elif (auth.has_membership(role='riskAnalyst')):
            if request.args(2)=='1':
                db(db.ValorMetrica.id==request.args(0)).update(LogAnalistaRiesgo=signature)
                db(db.ValorMetrica.id==request.args(0)).update(AprobacionAnalistaRiesgo='T')
            elif request.args(2)=='0':
                db(db.ValorMetrica.id==request.args(0)).update(LogAnalistaRiesgo=signature)
                db(db.ValorMetrica.id==request.args(0)).update(AprobacionAnalistaRiesgo='F')
        if request.args(3):
            redirect(URL('cvss', 'ValorMetrica', vars=dict(keywords=parametros)))
        else:
            redirect(URL('cvss', 'ValorMetrica'))
    if request.args(1) == 'ValorMetricaSeguridadTi':
        if (auth.has_membership(role='riskManager') or auth.has_membership(role='admin')):
            if request.args(2)=='1':
                db(db.ValorMetricaSeguridadTi.id==request.args(0)).update(LogJefeRiesgo=signature)
                db(db.ValorMetricaSeguridadTi.id==request.args(0)).update(AprobacionJefeRiesgo='T')
            elif request.args(2)=='0':
                db(db.ValorMetricaSeguridadTi.id==request.args(0)).update(LogJefeRiesgo=signature)
                db(db.ValorMetricaSeguridadTi.id==request.args(0)).update(AprobacionJefeRiesgo='F')
        elif (auth.has_membership(role='riskAnalyst')):
            if request.args(2)=='1':
                db(db.ValorMetricaSeguridadTi.id==request.args(0)).update(LogAnalistaRiesgo=signature)
                db(db.ValorMetricaSeguridadTi.id==request.args(0)).update(AprobacionAnalistaRiesgo='T')
            elif request.args(2)=='0':
                db(db.ValorMetricaSeguridadTi.id==request.args(0)).update(LogAnalistaRiesgo=signature)
                db(db.ValorMetricaSeguridadTi.id==request.args(0)).update(AprobacionAnalistaRiesgo='F')
        if request.args(3):
            redirect(URL('cvss', 'ValorMetricaSeguridadTi', vars=dict(keywords=parametros)))
        else:
            redirect(URL('cvss', 'ValorMetricaSeguridadTi'))
