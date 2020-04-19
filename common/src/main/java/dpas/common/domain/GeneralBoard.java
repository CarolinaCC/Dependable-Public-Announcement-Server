package dpas.common.domain;

import dpas.common.domain.exception.InvalidNumberOfPostsException;
import dpas.common.domain.exception.NullAnnouncementException;

import java.util.*;

public class GeneralBoard implements AnnouncementBoard {

    private final SortedSet<Announcement> _posts = Collections.synchronizedSortedSet(new TreeSet<>((a, b) -> {
        if (a.getSeq() != b.getSeq())
            return (int) (a.getSeq() - b.getSeq());
        else {
            return Base64.getEncoder().encodeToString(a.getUser().getPublicKey().getEncoded())
                    .compareTo(Base64.getEncoder().encodeToString(b.getUser().getPublicKey().getEncoded()));
        }
    }));

    public static final String GENERAL_BOARD_IDENTIFIER = "DPAS-GENERAL-BOARD";

    @Override
    public void post(Announcement announcement) throws NullAnnouncementException {
        if (announcement == null) {
            throw new NullAnnouncementException("Invalid Announcement: Cannot be null");
        }
        _posts.add(announcement);
    }

    @Override
    public List<Announcement> read(int number) throws InvalidNumberOfPostsException {
        if (number < 0) {
            throw new InvalidNumberOfPostsException("Invalid number of posts to read: number cannot be negative");
        }
        List<Announcement> posts;
        synchronized (_posts) {
             posts = new ArrayList<>(_posts);
        }
        if (number == 0 || number >= posts.size()) {
            return posts;
        }
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
        return GENERAL_BOARD_IDENTIFIER;
    }

}
