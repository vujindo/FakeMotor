import{v as l,c as m,w as t,o as d,a,u as o,X as c,b as e,d as p,n as u,e as f}from"./app-a17a276c.js";import{_}from"./GuestLayout-dabb177f.js";import{_ as w,a as b,b as h}from"./TextInput-644e8c5d.js";import{_ as x}from"./PrimaryButton-254b48ec.js";import"./ApplicationLogo-cab9eb11.js";const g=e("div",{class:"mb-4 text-sm text-gray-600"}," This is a secure area of the application. Please confirm your password before continuing. ",-1),v=["onSubmit"],V={class:"flex justify-end mt-4"},S={__name:"ConfirmPassword",setup(y){const s=l({password:""}),i=()=>{s.post(route("password.confirm"),{onFinish:()=>s.reset()})};return(C,r)=>(d(),m(_,null,{default:t(()=>[a(o(c),{title:"Confirm Password"}),g,e("form",{onSubmit:f(i,["prevent"])},[e("div",null,[a(w,{for:"password",value:"Password"}),a(b,{id:"password",type:"password",class:"mt-1 block w-full",modelValue:o(s).password,"onUpdate:modelValue":r[0]||(r[0]=n=>o(s).password=n),required:"",autocomplete:"current-password",autofocus:""},null,8,["modelValue"]),a(h,{class:"mt-2",message:o(s).errors.password},null,8,["message"])]),e("div",V,[a(x,{class:u(["ml-4",{"opacity-25":o(s).processing}]),disabled:o(s).processing},{default:t(()=>[p(" Confirm ")]),_:1},8,["class","disabled"])])],40,v)]),_:1}))}};export{S as default};
