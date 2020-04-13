package dpas.common.domain;

import dpas.common.domain.exception.InvalidNumberOfPostsException;
import dpas.common.domain.exception.InvalidUserException;
import dpas.common.domain.exception.NullAnnouncementException;
import dpas.common.domain.exception.NullUserException;

import java.security.PublicKey;
import java.util.*;

public class UserBoard implements AnnouncementBoard {
    private final User _owner;
    protected PublicKey _publicKey;

    private final SortedSet<Announcement> _posts = Collections.synchronizedSortedSet(new TreeSet<>((a, b) -> (int)(a.getSeq() - b.getSeq())));

    public UserBoard(User user) throws NullUserException {
        if (user == null)
            throw new NullUserException("Invalid User: Cannot be null");
        _owner = user;
        _publicKey = user.getPublicKey();
    }

    @Override
    public synchronized void post(Announcement announcement) throws NullAnnouncementException, InvalidUserException {
        checkArguments(announcement);
        _posts.add(announcement);
    }

    private void checkArguments(Announcement post) throws NullAnnouncementException, InvalidUserException {
        if (post == null) {
            throw new NullAnnouncementException("Invalid Post: Cannot be null");
        }
        if (post.getUser() != _owner) {
            throw new InvalidUserException("Invalid User: User is not owner of this board");
        }
    }

    public List<Announcement> read(int number) throws InvalidNumberOfPostsException {
        if (number < 0)
            throw new InvalidNumberOfPostsException("Invalid number of posts to read: number cannot be negative");
        List<Announcement> posts;
        synchronized (_posts) {
            posts = new ArrayList<>(_posts);
        }
        if (number == 0 || number >= posts.size())
            return posts;
        return posts.subList(posts.size() - number, posts.size());
    }

    @Override
    public long getSeq() {
        if (_posts.size() == 0) {
            return 0;
        }
        return _posts.last().getSeq();
    }

    @Override
    public String getIdentifier() {
        return Base64.getEncoder().encodeToString(_publicKey.getEncoded());
    }

}
