$ frida-trace -U -i strncmp sg.vantagepoint.uncrackable2
$ frida-trace  -U -i *bar* sg.vantagepoint.uncrackable2


[16:45 edu@ubuntu hooks] > python run_usb_spawn.py
pid: 17866
[*] Intercepting ...
[!] Received: [Starting hooks OWASP uncrackable2...]
[!] Received: [Hooks installed.]
[!] Received: [java.lang.System.exit(I)V  // We avoid exiting the application  :)]
[!] Received: [sg.vantagepoint.uncrackable2.CodeCheck.bar([B)Z]
[!] Received: [enovella]
[!] Received: [False]







signed int __fastcall Java_sg_vantagepoint_uncrackable2_CodeCheck_bar(JNIEnv *jni, jobject self, char* src_input)
{
  const char *input; // r6@2
  signed int result; // r0@4
  char *flag; // [sp+0h] [bp-28h]@2
  char *v8; // [sp+4h] [bp-24h]@2
  int v9; // [sp+8h] [bp-20h]@2
  int v10; // [sp+Ch] [bp-1Ch]@2
  int v11; // [sp+10h] [bp-18h]@2
  __int16 v12; // [sp+14h] [bp-14h]@2
  char v13; // [sp+16h] [bp-12h]@2
  int cookie; // [sp+18h] [bp-10h]@5

  if ( codecheck == 1 )
  {
    _aeabi_memclr(&v8 + 2, 18);
    flag = 'nahT';
    v8 = 'f sk';
    v9 = 'a ro';
    v10 = 't ll';
    v11 = 'f eh';
    v12 = 'si';
    v13 = 'h';
    input = ((*jni)->GetByteArrayElements)(jni, src_input, 0);
    if ( ((*jni)->GetArrayLength)(jni, src_input) == 23 && !strncmp(input, &flag, 23u) )
      goto SUCCESS;
  }
  result = 0;
  while ( _stack_chk_guard != cookie )
SUCCESS:
    result = 1;
  return result;
}
