package dpas.common.domain;

import dpas.common.domain.exception.InvalidNumberOfPostsException;
import dpas.common.domain.exception.InvalidUserException;
import dpas.common.domain.exception.NullAnnouncementException;
import dpas.common.domain.exception.NullUserException;

import java.security.PublicKey;
import java.util.*;
import java.util.stream.Collectors;

public class UserBoard implements AnnouncementBoard {

    private static final Comparator<Announcement> USER_BOARD_COMPARATOR = Comparator.comparing(a -> -a.getSeq());

    private final User owner;
    protected final PublicKey publicKey;
    private final SortedSet<Announcement> posts = Collections.synchronizedSortedSet(new TreeSet<>(USER_BOARD_COMPARATOR));

    public UserBoard(User user) throws NullUserException {
        if (user == null)
            throw new NullUserException("Invalid User: Cannot be null");
        this.owner = user;
        this.publicKey = user.getPublicKey();
    }

    @Override
    public void post(Announcement announcement) throws NullAnnouncementException, InvalidUserException {
        checkArguments(announcement);
        this.posts.add(announcement);
    }

    private void checkArguments(Announcement post) throws NullAnnouncementException, InvalidUserException {
        if (post == null) {
            throw new NullAnnouncementException("Invalid Post: Cannot be null");
        }
        if (!post.getUser().equals(this.owner)) {
            throw new InvalidUserException("Invalid User: User is not owner of this board");
        }
    }

    public List<Announcement> read(int number) throws InvalidNumberOfPostsException {
        if (number < 0) {
            throw new InvalidNumberOfPostsException("Invalid number of posts to read: number cannot be negative");
        }
        int size = number == 0 ? this.posts.size() : Math.min(this.posts.size(), number);
        List<Announcement> announcements;
        synchronized (posts) {
            announcements = posts.stream().limit(size).collect(Collectors.toList());
        }
        Collections.reverse(announcements);
        return announcements;
    }

    @Override
    public long getSeq() {
        if (this.posts.size() == 0) {
            return 0;
        }
        return this.posts.first().getSeq();
    }

    @Override
    public String getIdentifier() {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }
}
