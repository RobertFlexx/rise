with Ada.Command_Line;
with Ada.Text_IO;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded;
with Ada.Characters.Handling;
with Interfaces.C;
with Interfaces.C.Strings;
with System;

procedure Rise is
   package CL renames Ada.Command_Line;
   package SF renames Ada.Strings.Fixed;
   package UH renames Ada.Characters.Handling;

   use Ada.Text_IO;
   use Ada.Strings.Unbounded;
   use Interfaces.C;
   use Interfaces.C.Strings;

   Config_Path : constant String := "/etc/rise.conf";
   Pam_Service : constant String := "rise";
   Builtin_Safe_Path : constant String := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
   Max_Config  : constant size_t := 64 * 1024;

   type Uid_T is new unsigned;
   type Gid_T is new unsigned;

   function getuid return Uid_T;
   pragma Import (C, getuid, "getuid");

   function geteuid return Uid_T;
   pragma Import (C, geteuid, "geteuid");

   function rise_secure_read_config
     (Path : chars_ptr; Out_Text : access chars_ptr; Out_Len : access size_t; Max_Len : size_t)
      return int;
   pragma Import (C, rise_secure_read_config, "rise_secure_read_config");

   function rise_username_for_uid (Uid : Uid_T) return chars_ptr;
   pragma Import (C, rise_username_for_uid, "rise_username_for_uid");

   function rise_lookup_user
     (Name : chars_ptr;
      Out_Uid : access Uid_T;
      Out_Gid : access Gid_T;
      Out_Home : access chars_ptr;
      Out_Shell : access chars_ptr;
      Out_Name : access chars_ptr) return int;
   pragma Import (C, rise_lookup_user, "rise_lookup_user");

   function rise_user_in_group (User : chars_ptr; Group : chars_ptr) return int;
   pragma Import (C, rise_user_in_group, "rise_user_in_group");

   function rise_file_is_executable (Path : chars_ptr) return int;
   pragma Import (C, rise_file_is_executable, "rise_file_is_executable");

   function rise_canonical_executable (Path : chars_ptr; Out_Path : access chars_ptr) return int;
   pragma Import (C, rise_canonical_executable, "rise_canonical_executable");

   function rise_pam_auth
     (Service : chars_ptr; User : chars_ptr; Attempts : int; Noninteractive : int; Jokes : int) return int;
   pragma Import (C, rise_pam_auth, "rise_pam_auth");

   function rise_apply_safe_env
     (Target_Name : chars_ptr; Target_Home : chars_ptr; Target_Shell : chars_ptr;
      Secure_Path : chars_ptr; Env_Keep : chars_ptr) return int;
   pragma Import (C, rise_apply_safe_env, "rise_apply_safe_env");

   function rise_drop_privs (Target_Name : chars_ptr; Target_Uid : Uid_T; Target_Gid : Gid_T) return int;
   pragma Import (C, rise_drop_privs, "rise_drop_privs");

   function rise_ticket_check
     (Caller_Uid : Uid_T; Target_Uid : Uid_T; Tty_Tickets : int; Timeout_Seconds : unsigned; Require_Tty : int) return int;
   pragma Import (C, rise_ticket_check, "rise_ticket_check");

   function rise_ticket_update
     (Caller_Uid : Uid_T; Target_Uid : Uid_T; Tty_Tickets : int; Require_Tty : int) return int;
   pragma Import (C, rise_ticket_update, "rise_ticket_update");

   function rise_ticket_invalidate
     (Caller_Uid : Uid_T; Target_Uid : Uid_T; Tty_Tickets : int) return int;
   pragma Import (C, rise_ticket_invalidate, "rise_ticket_invalidate");

   procedure rise_log_decision
     (Caller : chars_ptr; Target : chars_ptr; Command : chars_ptr; Result : chars_ptr; Reason : chars_ptr);
   pragma Import (C, rise_log_decision, "rise_log_decision");

   procedure rise_free (Ptr : chars_ptr);
   pragma Import (C, rise_free, "rise_free");

   function execv (Path : chars_ptr; Argv : System.Address) return int;
   pragma Import (C, execv, "execv");

   procedure Die (Message : String) is
   begin
      Put_Line (Standard_Error, "rise: " & Message);
      CL.Set_Exit_Status (1);
      raise Program_Error;
   end Die;

   procedure Info (Message : String) is
   begin
      Put_Line ("rise: " & Message);
   end Info;

   function Trim (S : String) return String is
   begin
      return SF.Trim (S, Ada.Strings.Both);
   end Trim;

   function Lower (S : String) return String is
   begin
      return UH.To_Lower (S);
   end Lower;

   function Starts_With_CI (S, Prefix : String) return Boolean is
   begin
      return S'Length >= Prefix'Length
        and then Lower (S (S'First .. S'First + Prefix'Length - 1)) = Lower (Prefix);
   end Starts_With_CI;

   function Contains (S : String; Ch : Character) return Boolean is
   begin
      for C of S loop
         if C = Ch then
            return True;
         end if;
      end loop;
      return False;
   end Contains;

   function Strip_Comment (Line : String) return String is
      P : Natural := SF.Index (Line, "#");
   begin
      if P = 0 then
         return Trim (Line);
      elsif P = Line'First then
         return "";
      else
         return Trim (Line (Line'First .. P - 1));
      end if;
   end Strip_Comment;

   function Key_Of (Line : String) return String is
      P : Natural := SF.Index (Line, "=");
   begin
      if P = 0 then
         return "";
      end if;
      return Lower (Trim (Line (Line'First .. P - 1)));
   end Key_Of;

   function Val_Of (Line : String) return String is
      P : Natural := SF.Index (Line, "=");
   begin
      if P = 0 or else P = Line'Last then
         return "";
      end if;
      return Trim (Line (P + 1 .. Line'Last));
   end Val_Of;

   function Next_Line (Text : String; Pos : in out Positive) return String is
      Start : constant Positive := Pos;
      Stop  : Natural := Start;
   begin
      while Stop <= Text'Last and then Text (Stop) /= Character'Val (10) loop
         Stop := Stop + 1;
      end loop;

      Pos := Stop + 1;

      if Stop > Start and then Text (Stop - 1) = Character'Val (13) then
         return Text (Start .. Stop - 2);
      elsif Stop > Text'Last then
         return Text (Start .. Text'Last);
      else
         return Text (Start .. Stop - 1);
      end if;
   end Next_Line;

   function Parse_Bool (S : String; Name : String) return Boolean is
      L : constant String := Lower (Trim (S));
   begin
      if L = "yes" or else L = "true" or else L = "on" or else L = "1" then
         return True;
      elsif L = "no" or else L = "false" or else L = "off" or else L = "0" then
         return False;
      else
         Die ("bad boolean for " & Name & ": " & S);
         return False;
      end if;
   end Parse_Bool;

   function Parse_Natural (S : String; Name : String) return Natural is
   begin
      return Natural'Value (Trim (S));
   exception
      when others =>
         Die ("bad number for " & Name & ": " & S);
         return 0;
   end Parse_Natural;

   function C_String_Value_And_Free (P : chars_ptr; What : String) return String is
   begin
      if P = Null_Ptr then
         Die ("could not resolve " & What);
      end if;

      declare
         S : constant String := Value (P);
      begin
         rise_free (P);
         return S;
      end;
   end C_String_Value_And_Free;

   function Current_User return String is
      P : chars_ptr := rise_username_for_uid (getuid);
   begin
      return C_String_Value_And_Free (P, "current user");
   end Current_User;

   type User_Record is record
      Name  : Unbounded_String;
      Home  : Unbounded_String;
      Shell : Unbounded_String;
      Uid   : Uid_T := 0;
      Gid   : Gid_T := 0;
   end record;

   type Config_Defaults is record
      Timestamp          : Boolean := True;
      Timestamp_Timeout : Natural := 300;
      Tty_Tickets        : Boolean := True;
      Require_Tty        : Boolean := False;
      Jokes              : Boolean := True;
      Secure_Path        : Unbounded_String := To_Unbounded_String (Builtin_Safe_Path);
      Env_Keep           : Unbounded_String := To_Unbounded_String ("TERM,COLORTERM,LANG,LC_*");
   end record;

   function To_Int (B : Boolean) return int is
   begin
      if B then
         return 1;
      else
         return 0;
      end if;
   end To_Int;

   function Lookup_User (Name : String) return User_Record is
      C_Name  : chars_ptr := New_String (Name);
      C_Home  : aliased chars_ptr := Null_Ptr;
      C_Shell : aliased chars_ptr := Null_Ptr;
      C_Real  : aliased chars_ptr := Null_Ptr;
      Uid     : aliased Uid_T := 0;
      Gid     : aliased Gid_T := 0;
      R       : int;
   begin
      R := rise_lookup_user
        (C_Name, Uid'Access, Gid'Access, C_Home'Access, C_Shell'Access, C_Real'Access);
      Free (C_Name);

      if R /= 0 then
         Die ("unknown target user: " & Name);
      end if;

      declare
         Home  : constant String := C_String_Value_And_Free (C_Home, "home");
         Shell : constant String := C_String_Value_And_Free (C_Shell, "shell");
         Real  : constant String := C_String_Value_And_Free (C_Real, "name");
      begin
         return (Name => To_Unbounded_String (Real),
                 Home => To_Unbounded_String (Home),
                 Shell => To_Unbounded_String (Shell),
                 Uid => Uid,
                 Gid => Gid);
      end;
   end Lookup_User;

   function Read_Config return String is
      C_Path : chars_ptr := New_String (Config_Path);
      Outp   : aliased chars_ptr := Null_Ptr;
      Len    : aliased size_t := 0;
      R      : int;
   begin
      R := rise_secure_read_config (C_Path, Outp'Access, Len'Access, Max_Config);
      Free (C_Path);

      if R /= 0 then
         case Integer (R) is
            when -2 => Die (Config_Path & " must be a regular file, not a symlink/device");
            when -3 => Die (Config_Path & " must be owned by root");
            when -4 => Die (Config_Path & " must not be writable by group/others");
            when -5 => Die (Config_Path & " is too large");
            when -6 => Die (Config_Path & " must not have multiple hard links");
            when -7 => Die (Config_Path & " must not contain NUL bytes");
            when others => Die ("cannot securely read " & Config_Path);
         end case;
      end if;

      return C_String_Value_And_Free (Outp, "config text");
   end Read_Config;

   function Parse_Defaults (Text : String) return Config_Defaults is
      Pos : Positive := Text'First;
      In_Defaults : Boolean := False;
      D : Config_Defaults;
   begin
      if Text'Length = 0 then
         return D;
      end if;

      while Pos <= Text'Last loop
         declare
            Raw  : constant String := Next_Line (Text, Pos);
            Line : constant String := Strip_Comment (Raw);
         begin
            if Line = "" then
               null;
            elsif Line (Line'First) = '[' and then Line (Line'Last) = ']' then
               declare
                  Section : constant String := Lower (Trim (Line (Line'First + 1 .. Line'Last - 1)));
               begin
                  In_Defaults := Section = "defaults";
               end;
            elsif In_Defaults then
               declare
                  K : constant String := Key_Of (Line);
                  V : constant String := Val_Of (Line);
               begin
                  if K = "format" then
                     if Trim (V) /= "2" then
                        Die ("unsupported config format: " & V);
                     end if;
                  elsif K = "timestamp" then
                     D.Timestamp := Parse_Bool (V, K);
                  elsif K = "timestamp_timeout" then
                     D.Timestamp_Timeout := Parse_Natural (V, K);
                     if D.Timestamp_Timeout > 86_400 then
                        Die ("timestamp_timeout too large");
                     end if;
                  elsif K = "tty_tickets" then
                     D.Tty_Tickets := Parse_Bool (V, K);
                  elsif K = "require_tty" then
                     D.Require_Tty := Parse_Bool (V, K);
                  elsif K = "jokes" then
                     D.Jokes := Parse_Bool (V, K);
                  elsif K = "secure_path" then
                     D.Secure_Path := To_Unbounded_String (V);
                  elsif K = "env_keep" then
                     D.Env_Keep := To_Unbounded_String (V);
                  else
                     Die ("unknown defaults key: " & K);
                  end if;
               end;
            end if;
         end;
      end loop;

      return D;
   end Parse_Defaults;

   function Is_Executable (Path : String) return Boolean is
      C_Path : chars_ptr := New_String (Path);
      R      : int;
   begin
      R := rise_file_is_executable (C_Path);
      Free (C_Path);
      return R = 0;
   end Is_Executable;

   function Canonical_Executable (Path : String) return String is
      C_Path : chars_ptr := New_String (Path);
      Outp   : aliased chars_ptr := Null_Ptr;
      R      : int;
   begin
      R := rise_canonical_executable (C_Path, Outp'Access);
      Free (C_Path);

      if R /= 0 then
         case Integer (R) is
            when -2 => Die ("path is not absolute: " & Path);
            when -3 => Die ("path cannot be canonicalized: " & Path);
            when -4 => Die ("not a regular executable: " & Path);
            when others => Die ("invalid executable path: " & Path);
         end case;
      end if;

      return C_String_Value_And_Free (Outp, "canonical executable");
   end Canonical_Executable;

   function Resolve_Command (Cmd : String; Secure_Path : String) return String is
      Pos : Positive := Secure_Path'First;
   begin
      if Cmd = "" then
         Die ("empty command");
      end if;

      --  Absolute input is resolved through realpath(3) in the C layer before
      --  policy matching. This prevents aliases such as //bin/sh or
      --  /usr/bin/../bin/sh from bypassing exact-path allowlists.
      if Cmd (Cmd'First) = '/' then
         return Canonical_Executable (Cmd);
      end if;

      if Contains (Cmd, '/') then
         Die ("relative paths are refused; use an absolute path or a command name in the secure_path");
      end if;

      if Secure_Path = "" then
         Die ("secure_path is empty");
      end if;

      while Pos <= Secure_Path'Last loop
         declare
            Start : constant Positive := Pos;
            Stop  : Natural := Pos;
         begin
            while Stop <= Secure_Path'Last and then Secure_Path (Stop) /= ':' loop
               Stop := Stop + 1;
            end loop;

            if Stop > Start then
               declare
                  Dir  : constant String := Secure_Path (Start .. Stop - 1);
                  Full : constant String := Dir & "/" & Cmd;
               begin
                  if Dir = "" or else Dir (Dir'First) /= '/' then
                     Die ("secure_path entries must be absolute paths");
                  end if;

                  if Is_Executable (Full) then
                     return Canonical_Executable (Full);
                  end if;
               end;
            else
               Die ("secure_path contains an empty entry");
            end if;

            Pos := Stop + 1;
         end;
      end loop;

      Die ("command not found in secure_path: " & Cmd);
      return Cmd;
   end Resolve_Command;

   function Principal_Item_Matches (Item : String; Caller : String) return Boolean is
      I : constant String := Trim (Item);
   begin
      if Starts_With_CI (I, "user:") then
         return I (I'First + 5 .. I'Last) = Caller;
      elsif Starts_With_CI (I, "group:") then
         declare
            Group_Name : constant String := I (I'First + 6 .. I'Last);
            C_User  : chars_ptr := New_String (Caller);
            C_Group : chars_ptr := New_String (Group_Name);
            R       : int;
         begin
            R := rise_user_in_group (C_User, C_Group);
            Free (C_User);
            Free (C_Group);
            return R = 1;
         end;
      else
         return False;
      end if;
   end Principal_Item_Matches;

   function Principal_Matches (Who_List : String; Caller : String) return Boolean is
      L   : constant String := Trim (Who_List);
      Pos : Positive := L'First;
   begin
      if L = "" then
         return False;
      end if;

      while Pos <= L'Last loop
         declare
            Start : constant Positive := Pos;
            Stop  : Natural := Pos;
         begin
            while Stop <= L'Last and then L (Stop) /= ',' loop
               Stop := Stop + 1;
            end loop;

            if Principal_Item_Matches (L (Start .. Stop - 1), Caller) then
               return True;
            end if;

            Pos := Stop + 1;
         end;
      end loop;

      return False;
   end Principal_Matches;

   function Target_List_Matches (List : String; Target : String) return Boolean is
      L   : constant String := Trim (List);
      Pos : Positive := L'First;
   begin
      if Lower (L) = "any" then
         return True;
      end if;

      if L = "" then
         return False;
      end if;

      while Pos <= L'Last loop
         declare
            Start : constant Positive := Pos;
            Stop  : Natural := Pos;
         begin
            while Stop <= L'Last and then L (Stop) /= ',' loop
               Stop := Stop + 1;
            end loop;

            declare
               Item : constant String := Trim (L (Start .. Stop - 1));
            begin
               if Item = Target then
                  return True;
               end if;
            end;

            Pos := Stop + 1;
         end;
      end loop;

      return False;
   end Target_List_Matches;

   function Command_Item_Matches (Item : String; Resolved_Command : String) return Boolean is
      I : constant String := Trim (Item);
   begin
      if I = "" then
         return False;
      end if;

      if I (I'First) /= '/' then
         Die ("cmd entries must be absolute paths or 'any': " & I);
      end if;

      return Canonical_Executable (I) = Resolved_Command;
   end Command_Item_Matches;

   function Command_List_Matches (List : String; Resolved_Command : String) return Boolean is
      L   : constant String := Trim (List);
      Pos : Positive := L'First;
   begin
      if Lower (L) = "any" then
         return True;
      end if;

      if L = "" then
         return False;
      end if;

      while Pos <= L'Last loop
         declare
            Start : constant Positive := Pos;
            Stop  : Natural := Pos;
         begin
            while Stop <= L'Last and then L (Stop) /= ',' loop
               Stop := Stop + 1;
            end loop;

            declare
               Item : constant String := Trim (L (Start .. Stop - 1));
            begin
               if Command_Item_Matches (Item, Resolved_Command) then
                  return True;
               end if;
            end;

            Pos := Stop + 1;
         end;
      end loop;

      return False;
   end Command_List_Matches;

   type Decision_Kind is (No_Match, Rule_Allow, Rule_Deny);

   type Decision is record
      Kind    : Decision_Kind := No_Match;
      Auth    : Unbounded_String := To_Unbounded_String ("pam");
      Persist : Boolean := True;
      Timeout : Natural := 300;
      Reason  : Unbounded_String := To_Unbounded_String ("no matching rule");
   end record;

   type Rule_State is record
      In_Rule : Boolean := False;
      Name    : Unbounded_String := Null_Unbounded_String;
      Action  : Unbounded_String := To_Unbounded_String ("deny");
      Who     : Unbounded_String := Null_Unbounded_String;
      Target  : Unbounded_String := To_Unbounded_String ("root");
      Auth    : Unbounded_String := To_Unbounded_String ("pam");
      Cmd     : Unbounded_String := To_Unbounded_String ("any");
      Persist : Unbounded_String := To_Unbounded_String ("default");
      Timeout : Integer := -1;
   end record;

   function Finish_Rule
     (R : Rule_State;
      D : Config_Defaults;
      Caller : String;
      Target : String;
      Resolved_Command : String) return Decision
   is
      Action  : constant String := Lower (Trim (To_String (R.Action)));
      Who     : constant String := To_String (R.Who);
      Target_List : constant String := To_String (R.Target);
      Auth    : constant String := Lower (Trim (To_String (R.Auth)));
      Cmd     : constant String := To_String (R.Cmd);
      Persist_Str : constant String := Lower (Trim (To_String (R.Persist)));
      Outd    : Decision;
   begin
      if not R.In_Rule then
         return Outd;
      end if;

      if Who = "" then
         return Outd;
      end if;

      if not Principal_Matches (Who, Caller) then
         return Outd;
      end if;

      if not Target_List_Matches (Target_List, Target) then
         return Outd;
      end if;

      if not Command_List_Matches (Cmd, Resolved_Command) then
         return Outd;
      end if;

      if Action = "deny" then
         return (Kind => Rule_Deny,
                 Auth => To_Unbounded_String ("none"),
                 Persist => False,
                 Timeout => 0,
                 Reason => To_Unbounded_String ("matched deny rule " & To_String (R.Name)));
      elsif Action /= "allow" then
         return (Kind => Rule_Deny,
                 Auth => To_Unbounded_String ("none"),
                 Persist => False,
                 Timeout => 0,
                 Reason => To_Unbounded_String ("bad action in rule " & To_String (R.Name)));
      end if;

      if Auth /= "pam" and then Auth /= "none" then
         return (Kind => Rule_Deny,
                 Auth => To_Unbounded_String ("none"),
                 Persist => False,
                 Timeout => 0,
                 Reason => To_Unbounded_String ("bad auth mode in rule " & To_String (R.Name)));
      end if;

      Outd.Kind := Rule_Allow;
      Outd.Auth := To_Unbounded_String (Auth);
      Outd.Timeout := D.Timestamp_Timeout;
      Outd.Persist := D.Timestamp;

      if Persist_Str = "yes" or else Persist_Str = "true" or else Persist_Str = "on" then
         Outd.Persist := True;
      elsif Persist_Str = "no" or else Persist_Str = "false" or else Persist_Str = "off" then
         Outd.Persist := False;
      elsif Persist_Str = "default" or else Persist_Str = "" then
         null;
      else
         return (Kind => Rule_Deny,
                 Auth => To_Unbounded_String ("none"),
                 Persist => False,
                 Timeout => 0,
                 Reason => To_Unbounded_String ("bad persist value in rule " & To_String (R.Name)));
      end if;

      if R.Timeout >= 0 then
         Outd.Timeout := Natural (R.Timeout);
      end if;

      if Outd.Timeout > 86_400 then
         return (Kind => Rule_Deny,
                 Auth => To_Unbounded_String ("none"),
                 Persist => False,
                 Timeout => 0,
                 Reason => To_Unbounded_String ("timeout too large in rule " & To_String (R.Name)));
      end if;

      Outd.Reason := To_Unbounded_String ("matched allow rule " & To_String (R.Name));
      return Outd;
   end Finish_Rule;

   function Evaluate_Config
     (Text : String;
      D : Config_Defaults;
      Caller : String;
      Target : String;
      Resolved_Command : String) return Decision
   is
      Pos  : Positive := Text'First;
      Rule : Rule_State;
      Line_No : Natural := 0;
   begin
      if Text'Length = 0 then
         return (Kind => No_Match,
                 Auth => To_Unbounded_String ("pam"),
                 Persist => D.Timestamp,
                 Timeout => D.Timestamp_Timeout,
                 Reason => To_Unbounded_String ("empty config"));
      end if;

      while Pos <= Text'Last loop
         declare
            Raw  : constant String := Next_Line (Text, Pos);
            Line : constant String := Strip_Comment (Raw);
         begin
            Line_No := Line_No + 1;

            if Line = "" then
               null;
            elsif Line (Line'First) = '[' and then Line (Line'Last) = ']' then
               declare
                  Prior : constant Decision := Finish_Rule (Rule, D, Caller, Target, Resolved_Command);
               begin
                  if Prior.Kind /= No_Match then
                     return Prior;
                  end if;
               end;

               declare
                  Section : constant String := Lower (Trim (Line (Line'First + 1 .. Line'Last - 1)));
               begin
                  if Starts_With_CI (Section, "rule ") then
                     Rule :=
                       (In_Rule => True,
                        Name => To_Unbounded_String (Trim (Section (Section'First + 5 .. Section'Last))),
                        Action => To_Unbounded_String ("deny"),
                        Who => Null_Unbounded_String,
                        Target => To_Unbounded_String ("root"),
                        Auth => To_Unbounded_String ("pam"),
                        Cmd => To_Unbounded_String ("any"),
                        Persist => To_Unbounded_String ("default"),
                        Timeout => -1);
                  elsif Section = "defaults" then
                     Rule := (others => <>);
                  else
                     Die ("unknown section at line" & Natural'Image (Line_No));
                  end if;
               end;
            else
               declare
                  K : constant String := Key_Of (Line);
                  V : constant String := Val_Of (Line);
               begin
                  if K = "" then
                     Die ("bad config line" & Natural'Image (Line_No));
                  end if;

                  if not Rule.In_Rule then
                     if K /= "format"
                       and then K /= "timestamp"
                       and then K /= "timestamp_timeout"
                       and then K /= "tty_tickets"
                       and then K /= "require_tty"
                       and then K /= "jokes"
                       and then K /= "secure_path"
                       and then K /= "env_keep"
                     then
                        Die ("unknown defaults key at line" & Natural'Image (Line_No));
                     end if;
                  else
                     if K = "action" then
                        Rule.Action := To_Unbounded_String (Lower (V));
                     elsif K = "who" then
                        Rule.Who := To_Unbounded_String (V);
                     elsif K = "target" or else K = "as" then
                        Rule.Target := To_Unbounded_String (V);
                     elsif K = "auth" then
                        Rule.Auth := To_Unbounded_String (Lower (V));
                     elsif K = "cmd" then
                        Rule.Cmd := To_Unbounded_String (V);
                     elsif K = "persist" then
                        Rule.Persist := To_Unbounded_String (Lower (V));
                     elsif K = "timeout" then
                        Rule.Timeout := Integer (Parse_Natural (V, K));
                     else
                        Die ("unknown rule key at line" & Natural'Image (Line_No));
                     end if;
                  end if;
               end;
            end if;
         end;
      end loop;

      return Finish_Rule (Rule, D, Caller, Target, Resolved_Command);
   end Evaluate_Config;

   procedure Log (Caller, Target, Command, Result, Reason : String) is
      C_Caller  : chars_ptr := New_String (Caller);
      C_Target  : chars_ptr := New_String (Target);
      C_Command : chars_ptr := New_String (Command);
      C_Result  : chars_ptr := New_String (Result);
      C_Reason  : chars_ptr := New_String (Reason);
   begin
      rise_log_decision (C_Caller, C_Target, C_Command, C_Result, C_Reason);
      Free (C_Caller);
      Free (C_Target);
      Free (C_Command);
      Free (C_Result);
      Free (C_Reason);
   end Log;

   type Parsed_CLI is record
      Target_User     : Unbounded_String := To_Unbounded_String ("root");
      Noninteractive  : Boolean := False;
      Kill_Ticket     : Boolean := False;
      Check_Config    : Boolean := False;
      Command_Index   : Natural := 0;
   end record;

   function Parse_CLI return Parsed_CLI is
      I : Natural := 1;
      P : Parsed_CLI;
   begin
      while I <= Natural (CL.Argument_Count) loop
         declare
            A : constant String := CL.Argument (Positive (I));
         begin
            if A = "-n" or else A = "--non-interactive" then
               P.Noninteractive := True;
               I := I + 1;
            elsif A = "-k" or else A = "--forget" then
               P.Kill_Ticket := True;
               I := I + 1;
            elsif A = "-C" or else A = "--check-config" then
               P.Check_Config := True;
               I := I + 1;
            elsif A = "-u" or else A = "--user" then
               if I + 1 > Natural (CL.Argument_Count) then
                  Die ("missing user after " & A);
               end if;
               P.Target_User := To_Unbounded_String (CL.Argument (Positive (I + 1)));
               I := I + 2;
            elsif A = "-h" or else A = "--help" then
               Put_Line ("usage: rise [-n] [-u user] command [args...]");
               Put_Line ("       rise -k [-u user]");
               Put_Line ("       rise -C");
               CL.Set_Exit_Status (0);
               raise Program_Error;
            elsif Starts_With_CI (A, "-") then
               Die ("unknown option: " & A);
            else
               P.Command_Index := I;
               return P;
            end if;
         end;
      end loop;

      return P;
   end Parse_CLI;

   procedure Exec_Command (Resolved_Command : String; Command_Index : Natural) is
      Count  : constant Natural := Natural (CL.Argument_Count) - Command_Index + 1;
      Argv   : chars_ptr_array (0 .. size_t (Count));
      C_Path : chars_ptr := New_String (Resolved_Command);
      R      : int;
   begin
      Argv (0) := New_String (Resolved_Command);

      if Count > 1 then
         for I in 1 .. Count - 1 loop
            Argv (size_t (I)) := New_String (CL.Argument (Positive (Command_Index + I)));
         end loop;
      end if;

      Argv (size_t (Count)) := Null_Ptr;

      R := execv (C_Path, Argv (0)'Address);
      if R /= 0 then
         Die ("exec failed: " & Resolved_Command);
      end if;
   end Exec_Command;

   Parsed      : Parsed_CLI;
   Caller      : Unbounded_String;
   Target_Name : Unbounded_String;
   Target      : User_Record;
   Config      : Unbounded_String;
   Defaults    : Config_Defaults;
   Requested   : Unbounded_String;
   Resolved    : Unbounded_String;
   D           : Decision;

begin
   if geteuid /= 0 then
      Die ("not installed setuid-root, or filesystem is mounted nosuid");
   end if;

   Parsed := Parse_CLI;
   Caller := To_Unbounded_String (Current_User);
   Target_Name := Parsed.Target_User;
   Target := Lookup_User (To_String (Target_Name));

   Config := To_Unbounded_String (Read_Config);
   Defaults := Parse_Defaults (To_String (Config));

   if Parsed.Check_Config then
      D := Evaluate_Config (To_String (Config), Defaults, To_String (Caller), To_String (Target.Name), "/__rise_check_config__");
      Info ("config syntax ok");
      CL.Set_Exit_Status (0);
      return;
   end if;

   if Parsed.Kill_Ticket then
      declare
         R : constant int := rise_ticket_invalidate
           (getuid, Target.Uid, To_Int (Defaults.Tty_Tickets));
      begin
         if R = 0 then
            Log (To_String (Caller), To_String (Target.Name), "<ticket>", "forget", "ticket invalidated");
            Info ("forgot cached authentication ticket");
            return;
         else
            Die ("could not forget authentication ticket");
         end if;
      end;
   end if;

   if Parsed.Command_Index = 0 then
      Die ("usage: rise [-n] [-u user] command [args...]");
   end if;

   Requested := To_Unbounded_String (CL.Argument (Positive (Parsed.Command_Index)));
   Resolved := To_Unbounded_String (Resolve_Command (To_String (Requested), To_String (Defaults.Secure_Path)));

   D := Evaluate_Config
     (To_String (Config),
      Defaults,
      To_String (Caller),
      To_String (Target.Name),
      To_String (Resolved));

   case D.Kind is
      when No_Match =>
         Log (To_String (Caller), To_String (Target.Name), To_String (Resolved), "deny", To_String (D.Reason));
         Die ("permission denied: " & To_String (D.Reason));

      when Rule_Deny =>
         Log (To_String (Caller), To_String (Target.Name), To_String (Resolved), "deny", To_String (D.Reason));
         Die ("permission denied: " & To_String (D.Reason));

      when Rule_Allow =>
         if Lower (To_String (D.Auth)) = "none" then
            Log (To_String (Caller), To_String (Target.Name), To_String (Resolved), "allow", To_String (D.Reason) & " auth=none");
         elsif Lower (To_String (D.Auth)) = "pam" then
            declare
               Cached : Boolean := False;
            begin
               if D.Persist then
                  declare
                     T : constant int := rise_ticket_check
                       (getuid, Target.Uid, To_Int (Defaults.Tty_Tickets),
                        unsigned (D.Timeout), To_Int (Defaults.Require_Tty));
                  begin
                     if T = 0 then
                        Cached := True;
                        Log (To_String (Caller), To_String (Target.Name), To_String (Resolved), "allow", To_String (D.Reason) & " cached");
                     elsif T = -2 then
                        Log (To_String (Caller), To_String (Target.Name), To_String (Resolved), "deny", "tty required");
                        Die ("authentication requires a tty");
                     end if;
                  end;
               end if;

               if not Cached then
                  declare
                     C_Service : chars_ptr := New_String (Pam_Service);
                     C_Caller  : chars_ptr := New_String (To_String (Caller));
                     R         : int;
                     NI        : int := To_Int (Parsed.Noninteractive);
                     J         : int := To_Int (Defaults.Jokes);
                  begin
                     R := rise_pam_auth (C_Service, C_Caller, 3, NI, J);
                     Free (C_Service);
                     Free (C_Caller);

                     if R /= 0 then
                        Log (To_String (Caller), To_String (Target.Name), To_String (Resolved), "deny", "pam auth failed");
                        Die ("authentication failed");
                     end if;

                     if D.Persist then
                        declare
                           U : constant int := rise_ticket_update
                             (getuid, Target.Uid, To_Int (Defaults.Tty_Tickets), To_Int (Defaults.Require_Tty));
                        begin
                           if U /= 0 then
                              Log (To_String (Caller), To_String (Target.Name), To_String (Resolved), "allow", "pam ok, ticket update failed");
                           end if;
                        end;
                     end if;

                     Log (To_String (Caller), To_String (Target.Name), To_String (Resolved), "allow", To_String (D.Reason) & " pam ok");
                  end;
               end if;
            end;
         else
            Die ("internal error: bad auth mode");
         end if;
   end case;

   declare
      C_Name  : chars_ptr := New_String (To_String (Target.Name));
      C_Home  : chars_ptr := New_String (To_String (Target.Home));
      C_Shell : chars_ptr := New_String (To_String (Target.Shell));
      C_Path  : chars_ptr := New_String (To_String (Defaults.Secure_Path));
      C_Keep  : chars_ptr := New_String (To_String (Defaults.Env_Keep));
      R       : int;
   begin
      R := rise_apply_safe_env (C_Name, C_Home, C_Shell, C_Path, C_Keep);
      if R /= 0 then
         Die ("failed to apply safe environment");
      end if;

      R := rise_drop_privs (C_Name, Target.Uid, Target.Gid);
      if R /= 0 then
         Die ("failed to set target credentials");
      end if;

      Free (C_Name);
      Free (C_Home);
      Free (C_Shell);
      Free (C_Path);
      Free (C_Keep);
   end;

   Exec_Command (To_String (Resolved), Parsed.Command_Index);

exception
   when Program_Error =>
      null;
end Rise;
