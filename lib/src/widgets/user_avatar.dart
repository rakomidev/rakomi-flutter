import 'package:flutter/cupertino.dart';
import 'package:flutter/foundation.dart'
    show TargetPlatform, defaultTargetPlatform;
import 'package:flutter/material.dart';

import '../auth/auth_state.dart';
import '../auth/user.dart';
import 'provider.dart';

/// User avatar + tooltip showing email + session expiry. Tapping reveals a
/// menu (Material `PopupMenu` / Cupertino `showCupertinoModalPopup`) with
/// a "Sign out" action.
///
/// Optional `formatExpiry: String Function(DateTime)?`
/// prop. Default formatter is `'yyyy-MM-dd HH:mm'` UTC (no `intl`
/// dependency at 0.1.0 — consumers can pass an `intl`-aware formatter).
class RakomiUserAvatar extends StatelessWidget {
  const RakomiUserAvatar({super.key, this.size = 36, this.formatExpiry});

  final double size;
  final String Function(DateTime expiresAt)? formatExpiry;

  bool get _isCupertino => defaultTargetPlatform == TargetPlatform.iOS;

  String _defaultFormat(DateTime e) {
    final u = e.toUtc();
    String two(int v) => v.toString().padLeft(2, '0');
    return '${u.year}-${two(u.month)}-${two(u.day)} ${two(u.hour)}:${two(u.minute)}';
  }

  @override
  Widget build(BuildContext context) {
    final auth = RakomiProvider.maybeOf(context);
    if (auth == null) return const SizedBox.shrink();
    return StreamBuilder<AuthState>(
      stream: auth.authStateChanges,
      initialData: auth.authState,
      builder: (BuildContext c, AsyncSnapshot<AuthState> snap) {
        final s = snap.data ?? const AuthStateLoading();
        if (s is! AuthStateAuthenticated) return const SizedBox.shrink();
        final user = s.user;
        final session = s.session;
        final tooltip =
            'Signed in as ${user.email}\n'
            'Session expires ${(formatExpiry ?? _defaultFormat)(session.expiresAt)}';
        return Tooltip(
          message: tooltip,
          child: Semantics(
            label: 'User menu — ${user.email}',
            button: true,
            child: GestureDetector(
              onTap: () => _showMenu(c, auth, user),
              child: _avatar(user),
            ),
          ),
        );
      },
    );
  }

  Widget _avatar(User user) {
    final url = user.imageUrl;
    if (url != null && url.isNotEmpty) {
      return CircleAvatar(radius: size / 2, backgroundImage: NetworkImage(url));
    }
    final initial =
        (user.displayName ?? user.email).characters.firstOrNull ?? '?';
    return CircleAvatar(radius: size / 2, child: Text(initial.toUpperCase()));
  }

  Future<void> _showMenu(BuildContext context, dynamic auth, User user) async {
    if (_isCupertino) {
      await showCupertinoModalPopup<void>(
        context: context,
        builder: (BuildContext c) => CupertinoActionSheet(
          title: Text(user.email),
          actions: <Widget>[
            CupertinoActionSheetAction(
              isDestructiveAction: true,
              onPressed: () {
                Navigator.of(c).pop();
                auth.signOut();
              },
              child: const Text('Sign out'),
            ),
          ],
          cancelButton: CupertinoActionSheetAction(
            onPressed: () => Navigator.of(c).pop(),
            child: const Text('Cancel'),
          ),
        ),
      );
      return;
    }
    final RenderBox button = context.findRenderObject()! as RenderBox;
    final Offset position = button.localToGlobal(Offset.zero);
    await showMenu<void>(
      context: context,
      position: RelativeRect.fromLTRB(
        position.dx,
        position.dy + size,
        position.dx + size,
        position.dy,
      ),
      items: <PopupMenuEntry<void>>[
        PopupMenuItem<void>(enabled: false, child: Text(user.email)),
        const PopupMenuDivider(),
        PopupMenuItem<void>(
          onTap: () => auth.signOut(),
          child: const Text('Sign out'),
        ),
      ],
    );
  }
}
