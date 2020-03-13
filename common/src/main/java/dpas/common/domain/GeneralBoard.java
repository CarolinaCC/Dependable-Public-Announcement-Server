package dpas.common.domain;

import dpas.common.domain.exception.NullPostException;
import dpas.common.domain.exception.NullUserException;
import dpas.common.domain.exception.InvalidNumberOfPostsException;
import java.util.ArrayList;

public class GeneralBoard extends AnnouncementBoard {
    private ArrayList<Announcement> _posts;
    private int _sequenceNumber = 0;

    @Override
    public void post(User user, Announcement announcement) throws NullPostException, NullUserException {
         checkArguments(user, announcement);
        _posts.add(announcement);
        announcement.set_sequenceNumber(_sequenceNumber);
        _sequenceNumber++;
    }

    public void checkArguments(User user, Announcement post) throws NullUserException, NullPostException  {
        if (user == null) {
            throw new NullUserException();
        }
        if (post == null) {
            throw new NullPostException();
        }
    }

}
